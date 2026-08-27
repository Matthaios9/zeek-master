






#pragma once

#include <cstdint>
#include <unordered_map>

namespace zeek::notifier::detail {

class Modifiable;


class Receiver {
public:
    Receiver();
    virtual ~Receiver();






    virtual void Modified(Modifiable* m) = 0;





    virtual void Terminate() {}
};


class Registry {
public:
    ~Registry();












    void Register(Modifiable* m, Receiver* r);










    void Unregister(Modifiable* m, Receiver* Receiver);







    void Unregister(Modifiable* m);





    void Terminate();

private:
    friend class Modifiable;



    void Modified(Modifiable* m);

    using ModifiableMap = std::unordered_multimap<Modifiable*, Receiver*>;
    ModifiableMap registrations;
};




extern Registry registry;





class Modifiable {
public:




    void Modified() {
        if ( num_receivers )
            registry.Modified(this);
    }







    void Unregister() {
        if ( num_receivers )
            registry.Unregister(this);
    }

protected:
    friend class Registry;


    uint64_t num_receivers = 0;
};

}
