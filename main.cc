#include <catch2/catch.hpp>
#include <sstream>
#include <stdexcept>

#include "scl/math/fp.h"
#include "scl/math/ec_ops.h"
#include "scl/math/curves/secp256k1.h"
#include "scl/math/ec.h"
#include "scl/math/ops.h"
#include "scl/math/number.h"
#include "scl/util/prg.h"
#include <iostream>

using namespace scl;

using namespace std;
using Curve = math::EC<math::Secp256k1>;
using Field = math::FF<math::Secp256k1::Order>;


auto prg = util::PRG::Create("seed");
auto prgtwo = util::PRG::Create("seedtwo");
auto prgthree = util::PRG::Create("seedthree");
Curve g = Curve::Generator();
auto ord = math::Number::FromString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"); /*is the same value of p*/
auto curvename = Curve::Name();
Field x(15); /*secret key*/
Curve y = g*x; /*public key*/

/*the prover chooses r randomly in F_p*/
Field r = Field::Random(prg);
/*the prover computes a=g^r and sends a to verifier*/
Curve a = g*r;
/*the verifier chooses e randomly in F_p and sends e to the prover*/
Field e = Field::Random(prgtwo);
/*the prover computes z and sends zto the verifier*/
auto z = r+e*x;
/*the verifier accepts iff a*y^e=g^z*/
auto pt1 = a+y*e;
auto pt2 = g*z;
auto output1=pt1-pt2;
bool check = output1.PointAtInfinity();



int main() {

    cout << g << '\n';
    cout << curvename << '\n';
    cout << r << '\n';
    cout << x << '\n';
    cout << a << '\n';
    cout << e << '\n';
    cout << z << '\n';
    cout << pt1 << '\n';
    cout << pt2 << '\n';
    cout << output1 << '\n';
    
if (check){
    cout <<"pasó"<<'\n';
} else {
    cout <<"no pasó"<<'\n';
} 

   
}
