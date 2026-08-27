

#include "zeek/iosource/Manager.h"

#include <cassert>



#include <sys/types.h>
#include <sys/event.h>

#include <sys/time.h>
#include <unistd.h>

#include "zeek/RunState.h"
#include "zeek/iosource/Component.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/PktDumper.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/plugin/Manager.h"

extern int signal_val;

namespace zeek::iosource {

Manager::WakeupHandler::WakeupHandler() {
    if ( ! iosource_mgr->RegisterFd(flare.FD(), this) )
        reporter->FatalError("Failed to register WakeupHandler's fd with iosource_mgr");
}

Manager::WakeupHandler::~WakeupHandler() { iosource_mgr->UnregisterFd(flare.FD(), this); }

void Manager::WakeupHandler::Process() { flare.Extinguish(); }

void Manager::WakeupHandler::Ping(std::string_view where) {


    if ( signal_val != 0 )
        DBG_LOG(DBG_MAINLOOP, "Pinging WakeupHandler from %.*s", static_cast<int>(where.size()), where.data());

    flare.Fire(true);
}

Manager::Manager() {
    event_queue = kqueue();
    if ( event_queue == -1 )
        reporter->FatalError("Failed to initialize kqueue: %s", strerror(errno));
}

Manager::~Manager() {
    delete wakeup;
    wakeup = nullptr;


    for ( auto& src : sources )
        src->src->Done();

    for ( auto& src : sources ) {
        if ( src->manage_lifetime )
            delete src->src;

        delete src;
    }

    sources.clear();

    for ( PktDumper* dumper : pkt_dumpers ) {
        dumper->Done();
        delete dumper;
    }

    pkt_dumpers.clear();


    delete pkt_src;

#ifndef _MSC_VER







    if ( event_queue != -1 )
        close(event_queue);
#endif
}

void Manager::InitPostScript() {
    wakeup = new WakeupHandler();
    poll_interval = BifConst::io_poll_interval_default;
}

void Manager::RemoveAll() {

    dont_counts = sources.size();
}

void Manager::Wakeup(std::string_view where) {
    if ( wakeup )
        wakeup->Ping(where);
}

void Manager::ReapSource(Source* src) {
    auto* iosource = src->src;
    assert(! iosource->IsOpen());

    DBG_LOG(DBG_MAINLOOP, "Reaping %s", src->src->Tag());
    iosource->Done();

    if ( src->manage_lifetime )
        delete iosource;

    if ( src->dont_count )
        dont_counts--;

    delete src;
}

void Manager::FindReadySources(ReadySources* ready) {
    ready->clear();

    double timeout = -1;
    IOSource* timeout_src = nullptr;
    bool time_to_poll = false;

    ++poll_counter;
    if ( poll_counter % poll_interval == 0 ) {
        poll_counter = 0;
        time_to_poll = true;
    }


    for ( auto i = sources.begin(); i != sources.end();  ) {
        auto* src = *i;
        auto iosource = src->src;
        if ( iosource->IsOpen() ) {
            double next = iosource->GetNextTimeout();

            if ( timeout == -1 || (next >= 0.0 && next < timeout) ) {
                timeout = next;
                timeout_src = iosource;
            }







            if ( next == 0 && (! time_to_poll || iosource != timeout_src) ) {
                ready->push_back({iosource, -1, 0});
            }
            else if ( iosource == pkt_src ) {
                if ( pkt_src->IsLive() ) {
                    if ( ! time_to_poll )



                        ready->push_back({pkt_src, -1, 0});
                }
            }
            ++i;
        }
        else {
            ReapSource(src);
            i = sources.erase(i);
        }
    }



    if ( Size() == 0 && (! BifConst::exit_only_after_terminate || run_state::terminating) ) {
        ready->clear();
        return;
    }

    DBG_LOG(DBG_MAINLOOP, "timeout: %f   ready size: %zu   time_to_poll: %d\n", timeout, ready->size(), time_to_poll);




    if ( ready->empty() || time_to_poll )
        Poll(ready, timeout, timeout_src);
}

void Manager::Poll(ReadySources* ready, double timeout, IOSource* timeout_src) {
    struct timespec kqueue_timeout;
    ConvertTimeout(timeout, kqueue_timeout);

    int ret = kevent(event_queue, nullptr, 0, events.data(), events.size(), &kqueue_timeout);
    if ( ret == -1 ) {


        if ( errno != EINTR )
            reporter->InternalWarning("Error calling kevent: %s", strerror(errno));
    }
    else if ( ret == 0 ) {


        if ( timeout_src )
            ready->push_back({timeout_src, -1, 0});
    }
    else {


        bool timeout_src_added = false;
        for ( int i = 0; i < ret; i++ ) {
            if ( events[i].filter == EVFILT_READ ) {
                std::map<int, IOSource*>::const_iterator it = fd_map.find(events[i].ident);
                if ( it != fd_map.end() )
                    ready->push_back({it->second, static_cast<int>(events[i].ident), IOSource::ProcessFlags::READ});
            }
            else if ( events[i].filter == EVFILT_WRITE ) {
                std::map<int, IOSource*>::const_iterator it = write_fd_map.find(events[i].ident);
                if ( it != write_fd_map.end() )
                    ready->push_back({it->second, static_cast<int>(events[i].ident), IOSource::ProcessFlags::WRITE});
            }



            timeout_src_added |= ready->empty() ? false : ready->back().src == timeout_src;
        }


        if ( timeout_src && timeout == 0.0 && ! timeout_src_added )
            ready->push_back({timeout_src, -1, 0});
    }
}

void Manager::ConvertTimeout(double timeout, struct timespec& spec) {



    if ( timeout < 0 ) {
        spec.tv_sec = 0;
        spec.tv_nsec = 1e8;
    }
    else {
        spec.tv_sec = static_cast<time_t>(timeout);
        spec.tv_nsec = static_cast<long>((timeout - spec.tv_sec) * 1e9);
    }
}

bool Manager::RegisterFd(int fd, IOSource* src, int flags) {
    std::vector<struct kevent> new_events;

    if ( (flags & IOSource::READ) != 0 ) {
        if ( ! fd_map.contains(fd) ) {
            new_events.push_back({});
            EV_SET(&(new_events.back()), fd, EVFILT_READ, EV_ADD, 0, 0, nullptr);
        }
    }
    if ( (flags & IOSource::WRITE) != 0 ) {
        if ( ! write_fd_map.contains(fd) ) {
            new_events.push_back({});
            EV_SET(&(new_events.back()), fd, EVFILT_WRITE, EV_ADD, 0, 0, nullptr);
        }
    }

    if ( ! new_events.empty() ) {
        int ret = kevent(event_queue, new_events.data(), new_events.size(), nullptr, 0, nullptr);
        if ( ret != -1 ) {
            DBG_LOG(DBG_MAINLOOP, "Registered fd %d from %s", fd, src->Tag());
            for ( const auto& a : new_events )
                events.push_back({});

            if ( (flags & IOSource::READ) != 0 )
                fd_map[fd] = src;
            if ( (flags & IOSource::WRITE) != 0 )
                write_fd_map[fd] = src;

            Wakeup("RegisterFd");
            return true;
        }
        else {
            reporter->Error("Failed to register fd %d from %s: %s (flags %d)", fd, src->Tag(), strerror(errno), flags);
            return false;
        }
    }

    return true;
}

bool Manager::UnregisterFd(int fd, IOSource* src, int flags) {
    std::vector<struct kevent> new_events;

    if ( (flags & IOSource::READ) != 0 ) {
        if ( fd_map.contains(fd) ) {
            new_events.push_back({});
            EV_SET(&(new_events.back()), fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        }
    }
    if ( (flags & IOSource::WRITE) != 0 ) {
        if ( write_fd_map.contains(fd) ) {
            new_events.push_back({});
            EV_SET(&(new_events.back()), fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        }
    }

    if ( ! new_events.empty() ) {
        int ret = kevent(event_queue, new_events.data(), new_events.size(), nullptr, 0, nullptr);
        if ( ret != -1 ) {
            DBG_LOG(DBG_MAINLOOP, "Unregistered fd %d from %s", fd, src->Tag());
            for ( const auto& a : new_events )
                events.pop_back();

            if ( (flags & IOSource::READ) != 0 )
                fd_map.erase(fd);
            if ( (flags & IOSource::WRITE) != 0 )
                write_fd_map.erase(fd);

            Wakeup("UnregisterFd");
            return true;
        }




    }
    else {
        reporter->Error("Attempted to unregister an unknown file descriptor %d from %s", fd, src->Tag());
        return false;
    }

    return true;
}

void Manager::Register(IOSource* src, bool dont_count, bool manage_lifetime) {


    for ( const auto& iosrc : sources ) {
        if ( iosrc->src == src ) {
            if ( iosrc->dont_count != dont_count )

                dont_counts += (dont_count ? 1 : -1);

            return;
        }
    }

    src->InitSource();
    Source* s = new Source;
    s->src = src;
    s->dont_count = dont_count;
    s->manage_lifetime = manage_lifetime;
    if ( dont_count )
        ++dont_counts;

    sources.push_back(s);
}

void Manager::Register(PktSrc* src) {
    pkt_src = src;

    Register(src, false, false);





    if ( src->IsLive() )
        poll_interval = BifConst::io_poll_interval_live;
    else if ( run_state::pseudo_realtime )
        poll_interval = 1;
}





static std::pair<std::string, std::string> split_prefix(std::string path) {


    std::string prefix;

    std::string::size_type i = path.find("::");
    if ( i != std::string::npos ) {
        prefix = path.substr(0, i);
        path = path.substr(i + 2, std::string::npos);
    }

    return std::make_pair(prefix, path);
}

PktSrc* Manager::OpenPktSrc(const std::string& path, bool is_live) {
    auto [prefix, npath] = split_prefix(path);




    PktSrcComponent* component = nullptr;
    std::list<PktSrcComponent*> all_components = plugin_mgr->Components<PktSrcComponent>();



    if ( ! is_live && prefix.empty() ) {
        uint32_t magic_num = 0;
        if ( auto f = fopen(path.c_str(), "rb") ) {
            size_t read = fread(&magic_num, 1, sizeof(magic_num), f);
            fclose(f);

            if ( read == sizeof(magic_num) )
                for ( const auto& c : all_components ) {
                    if ( c->DoesTrace() && c->HandlesMagicNumber(magic_num) ) {
                        component = c;
                        break;
                    }
                }
        }
    }

    if ( ! component ) {

        if ( prefix.empty() )
            prefix = "pcap";

        for ( const auto& c : all_components ) {
            if ( (is_live && ! c->DoesLive()) || (! is_live && ! c->DoesTrace()) )
                continue;


            if ( c->HandlesPrefix(prefix) ) {
                component = c;
                break;
            }
        }
    }

    if ( ! component )
        reporter->FatalError("type of packet source '%s' not recognized, or mode not supported", prefix.c_str());



    PktSrc* ps = (*component->Factory())(npath, is_live);
    assert(ps);

    DBG_LOG(DBG_PKTIO, "Created packet source of type %s for %s", component->Name().c_str(), npath.c_str());

    Register(ps);
    return ps;
}

PktDumper* Manager::OpenPktDumper(const std::string& path, bool append) {
    auto [prefix, npath] = split_prefix(path);
    if ( prefix.empty() )
        prefix = "pcap";



    PktDumperComponent* component = nullptr;

    std::list<PktDumperComponent*> all_components = plugin_mgr->Components<PktDumperComponent>();
    for ( const auto& c : all_components ) {
        if ( c->HandlesPrefix(prefix) ) {
            component = c;
            break;
        }
    }

    if ( ! component )
        reporter->FatalError("type of packet dumper '%s' not recognized", prefix.c_str());



    PktDumper* pd = (*component->Factory())(npath, append);
    assert(pd);

    if ( ! pd->IsOpen() && pd->IsError() )

        pd->Error("could not open");

    DBG_LOG(DBG_PKTIO, "Created packer dumper of type %s for %s", component->Name().c_str(), npath.c_str());

    pd->Init();
    pkt_dumpers.push_back(pd);

    return pd;
}

}
