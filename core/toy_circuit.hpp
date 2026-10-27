// M1 risk spike: the smallest circuit that exercises the full Groth16 path.
// Statement: "I know x such that x^3 + x + 5 == out", with out public.
// R1CS (each constraint is  A * B = C):
//   x  * x = x2
//   x2 * x = x3
//   (x3 + x + 5) * 1 = out
#pragma once

#include <libsnark/gadgetlib1/protoboard.hpp>

#include "snark.hpp"

namespace zk {

struct ToyCircuit {
    libsnark::protoboard<Fr> pb;
    libsnark::pb_variable<Fr> out, x, x2, x3;

    ToyCircuit() {
        out.allocate(pb, "out"); // allocated first => it is the public input
        x.allocate(pb, "x");
        x2.allocate(pb, "x2");
        x3.allocate(pb, "x3");
        pb.set_input_sizes(1);
        pb.add_r1cs_constraint(libsnark::r1cs_constraint<Fr>(x, x, x2), "x*x=x2");
        pb.add_r1cs_constraint(libsnark::r1cs_constraint<Fr>(x2, x, x3), "x2*x=x3");
        pb.add_r1cs_constraint(libsnark::r1cs_constraint<Fr>(x3 + x + 5, 1, out), "x3+x+5=out");
    }

    void generate_witness(long x_value) {
        Fr xv(x_value);
        pb.val(x) = xv;
        pb.val(x2) = xv * xv;
        pb.val(x3) = xv * xv * xv;
        pb.val(out) = pb.val(x3) + xv + Fr(5);
    }
};

} // namespace zk
