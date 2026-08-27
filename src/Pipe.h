

#pragma once

namespace zeek::detail {

class Pipe {
public:










    explicit Pipe(int flags0 = 0, int flags1 = 0, int status_flags0 = 0, int status_flags1 = 0, int* fds = nullptr);




    ~Pipe();




    Pipe(const Pipe& other);





    Pipe& operator=(const Pipe& other);




    int ReadFD() const { return fds[0]; }




    int WriteFD() const { return fds[1]; }





    void SetFlags(int flags);





    void UnsetFlags(int flags);

private:
    int fds[2] = {-1, -1};
    int flags[2] = {0};
    int status_flags[2] = {0};
};




class PipePair {
public:










    PipePair(int flags, int status_flags, int* fds = nullptr);




    Pipe& In() { return pipes[swapped]; }




    Pipe& Out() { return pipes[! swapped]; }




    const Pipe& In() const { return pipes[swapped]; }




    const Pipe& Out() const { return pipes[! swapped]; }





    int InFD() const { return In().ReadFD(); }





    int OutFD() const { return Out().WriteFD(); }






    void Swap() { swapped = ! swapped; }

private:
    Pipe pipes[2];
    bool swapped = false;
};

}
