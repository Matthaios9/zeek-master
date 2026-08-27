















#include "zeek/RandTest.h"

#include <cmath>
#include <cstring>

constexpr double log2of10 = 3.32192809488736234787;


static double rt_log2(double x) { return log2of10 * log10(x); }


constexpr double RT_INCIRC = 281474943156225.0;

namespace zeek::detail {

void RandTest::add(const void* buf, int bufl) {
    const unsigned char* bp = static_cast<const unsigned char*>(buf);
    int oc;

    while ( bufl-- > 0 ) {
        oc = *bp++;
        ccount[oc]++;
        totalc++;



        monte[mp++] = oc;
        if ( mp >= RT_MONTEN )
        {
            mp = 0;
            mcount++;
            montex = 0;
            montey = 0;
            for ( int mj = 0; mj < RT_MONTEN / 2; mj++ ) {
                montex = (montex * 256.0) + monte[mj];
                montey = (montey * 256.0) + monte[static_cast<size_t>((RT_MONTEN / 2) + mj)];
            }
            if ( montex * montex + montey * montey <= RT_INCIRC ) {
                inmont++;
            }
        }


        if ( sccfirst ) {
            sccfirst = 0;
            sccu0 = oc;
        }
        else {
            scct1 = scct1 + scclast * oc;
        }

        scct2 = scct2 + oc;
        scct3 = scct3 + (oc * oc);
        scclast = oc;
    }
}

void RandTest::end(double* r_ent, double* r_chisq, double* r_mean, double* r_montepicalc, double* r_scc) {
    int i;
    double ent = 0.0;
    double chisq = 0.0;
    double datasum = 0.0;
    double prob[256];


    scct1 = scct1 + scclast * sccu0;
    scct2 = scct2 * scct2;
    double scc = totalc * scct3 - scct2;
    if ( scc == 0.0 )
        scc = -100000;
    else
        scc = (totalc * scct1 - scct2) / scc;






    cexp = totalc / 256.0;
    for ( i = 0; i < 256; i++ ) {
        double a = ccount[i] - cexp;

        prob[i] = (static_cast<double>(ccount[i])) / totalc;
        chisq += (a * a) / cexp;
        datasum += (static_cast<double>(i)) * ccount[i];
    }


    for ( i = 0; i < 256; i++ ) {
        if ( prob[i] > 0.0 ) {
            ent += prob[i] * rt_log2(1 / prob[i]);
        }
    }



    montepi = mcount == 0 ? 0 : 4.0 * ((static_cast<double>(inmont)) / mcount);


    *r_ent = ent;
    *r_chisq = chisq;
    *r_mean = datasum / totalc;
    *r_montepicalc = montepi;
    *r_scc = scc;
}

}
