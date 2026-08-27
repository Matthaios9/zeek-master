

#pragma once

#include <cmath>
#include <cstdint>

namespace zeek::detail {

class PriorityQueue;

class PQ_Element {
public:
    explicit PQ_Element(double t) : time(t) {}
    virtual ~PQ_Element() = default;

    double Time() const { return time; }

    int Offset() const { return offset; }
    void SetOffset(int off) { offset = off; }

    void MinimizeTime() { time = -HUGE_VAL; }

protected:
    PQ_Element() = default;
    double time = 0.0;
    int offset = -1;
};

class PriorityQueue {
public:
    explicit PriorityQueue(int initial_size = 16);
    ~PriorityQueue();


    PQ_Element* Top() const {
        if ( heap_size == 0 )
            return nullptr;

        return heap[0];
    }



    PQ_Element* Remove();



    PQ_Element* Remove(PQ_Element* e);



    bool Add(PQ_Element* e);

    int Size() const { return heap_size; }
    int PeakSize() const { return peak_heap_size; }
    uint64_t CumulativeNum() const { return cumulative_num; }

protected:
    bool Resize(int new_size);

    void BubbleUp(int bin);
    void BubbleDown(int bin);

    int Parent(int bin) const { return bin >> 1; }

    int LeftChild(int bin) const { return bin << 1; }

    int RightChild(int bin) const { return LeftChild(bin) + 1; }

    void SetElement(int bin, PQ_Element* e) {
        heap[bin] = e;
        e->SetOffset(bin);
    }

    void Swap(int bin1, int bin2) {
        PQ_Element* t = heap[bin1];
        SetElement(bin1, heap[bin2]);
        SetElement(bin2, t);
    }

    PQ_Element** heap = nullptr;
    int heap_size = 0;
    int peak_heap_size = 0;
    int max_heap_size = 0;
    uint64_t cumulative_num = 0;
};

}
