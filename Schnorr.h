#ifndef EXAMPLE_PARTY_H
#define EXAMPLE_PARTY_H

#include <memory>
#include <stdexcept>
#include <utility>

#include "scl/math/fp.h"
#include "scl/math/ec_ops.h"
#include "scl/math/curves/secp256k1.h"
#include <scl/protocol/base.h>
#include <scl/protocol/protocol.h>

namespace scl::seri {
template <typename T>
struct Serializer<math::EC<T>> {
    static constexpr std::size_t SizeOf(const math::EC<T>& ignored) {
    (void)ignored;
    return math::EC<T>::ByteSize();
  }

  /**
   * @brief Write an math::FF element to a buffer.
   * @param elem the element.
   * @param buf the buffer.
   *
   * Calls math::FF::Write.
   */
  static std::size_t Write(const math::EC<T>& elem, unsigned char* buf) {
    elem.Write(buf);
    return SizeOf(elem);
  }

  /**
   * @brief Read an math::FF element from a buffer.
   * @param elem output variable holding the read element after reading.
   * @param buf the buffer.
   * @return the number of bytes read.
   *
   * Calls math::FF::Read() and returns math::FF::ByteSize();
   */
  static std::size_t Read(math::EC<T>& elem, const unsigned char* buf) {
    elem = math::EC<T>::Read(buf);
    return math::EC<T>::ByteSize();
  }
};
}

using Curve =scl::math::EC<scl::math::Secp256k1>;
using Field = scl::math::FF<scl::math::Secp256k1::Order>;

class Prover final : public scl::proto::Protocol {
 public:
  /**
   * Helper method for creating the first round of the protocol.
   */
  static std::unique_ptr<scl::proto::Protocol> Create(int sk) {
    // std::vector<int> v;
    return std::make_unique<Prover>(sk);
  }

  /**
   * Constructor. Used by the Run function to initiate the next round of the
   * protocol.
   *
   * @param my_message the message to send in this round.
   * @param rounds_left how many rounds are remaining.
   * @param received_messages messages received so far.
   */

  Prover(int sk) : m_sk(sk) {}

  std::unique_ptr<scl::proto::Protocol> Run(scl::proto::Env& env) override {
    auto prg = scl::util::PRG::Create("seed");
    Curve g = Curve::Generator();
    std::string curvename = Curve::Name();
    Curve y = g * m_sk; /*public key*/

    scl::net::Packet pkt_send_y;
    pkt_send_y << y;
    

    // Send the packet to the next party.
    env.network.Party(1)->Send(pkt_send_y);
    std::cout << "Prover sends pk:=y:" << y << '\n';

    /*the prover chooses r randomly in F_p*/
    Field r = Field::Random(prg);
    /*the prover computes a=g^r and sends a to verifier*/
    Curve a = g*r;

    scl::net::Packet pkt_send;
    pkt_send << a;

    // Send the packet to the next party.
    env.network.Party(1)->Send(pkt_send);
    std::cout << "Prover sends a:" << a << '\n';

    // Receive challenge e and process it

    auto pkt_recv = env.network.Party(1)->Recv();
    if (!pkt_recv.has_value()) {
      throw std::logic_error("other party did not send a message");
    }
    auto& e_received = pkt_recv.value();
    const auto e_message = e_received.Read<Field>();
    std::cout << "Prover receives e:" << e_message << '\n';

    auto z = r + e_message * m_sk;
    
    // Create a Packet for sending, and add our message to it.
    scl::net::Packet pkt_send_z;
    pkt_send_z << z;
    // Send the packet to the next party.
    env.network.Party(1)->Send(pkt_send_z);
    std::cout << "Prover sends z:" << z << '\n';

    return nullptr;
  }

  /**
   * This method returns the protocol output, if any. The default value if an
   * std::any is an "empty" value, so we only get an actual output when the
   * protocol terminates.
   */
  // std::any Output() const override {
  //   return m_output;
  // }

 private:
  Field m_sk;
};

class Verifier final : public scl::proto::Protocol {
 public:
  /**
   * Helper method for creating the first round of the protocol.
   */
  static std::unique_ptr<scl::proto::Protocol> Create() {
    // std::vector<int> v;
    return std::make_unique<Verifier>();
  }

  /**
   * Constructor. Used by the Run function to initiate the next round of the
   * protocol.
   *
   * @param my_message the message to send in this round.
   * @param rounds_left how many rounds are remaining.
   * @param received_messages messages received so far.
   */
  // Prover(int sk)
  //     : m_my_message(my_message),
  //       m_rounds_left(rounds_left),
  //       m_received_messages(received_messages) {}

  Verifier(){}

  std::unique_ptr<scl::proto::Protocol> Run(scl::proto::Env& env) override {
    auto prg = scl::util::PRG::Create("seed_v");
    Curve g = Curve::Generator();
    std::string curvename = Curve::Name();

    /* Receive pk */ 
    auto pkt_recv_y = env.network.Party(0)->Recv();
    if (!pkt_recv_y.has_value()) {
      throw std::logic_error("other party did not send a message");
    }
    auto& y_received = pkt_recv_y.value();
    const auto y = y_received.Read<Curve>();
    std::cout << "Verifier sends pk:=y:" << y << '\n';

    /* Receive and process a */ 
    auto pkt_recv = env.network.Party(0)->Recv();
    if (!pkt_recv.has_value()) {
      throw std::logic_error("other party did not send a message");
    }
    auto& a_received = pkt_recv.value();
    const auto a_message = a_received.Read<Curve>();
    std::cout << "Verifier receives a:" << a_message << '\n';

    // Sample and send e
    Field e = Field::Random(prg);
    // Send the packet to the next party.
    scl::net::Packet pkt_send;
    pkt_send << e;
    env.network.Party(0)->Send(pkt_send);
    std::cout << "Verifier sends e:" << e << '\n';

    // Receive and process z
    auto pkt_recv_z = env.network.Party(0)->Recv();
    if (!pkt_recv_z.has_value()) {
      throw std::logic_error("other party did not send a message");
    }
    auto& z_received = pkt_recv_z.value();
    const auto z_message = z_received.Read<Field>();
    std::cout << "Verifier receives z:" << z_message << '\n';

    /*the verifier accepts iff a*y^e=g^z*/
    auto pt1 = a_message + y * e;
    auto pt2 = g * z_message;
    auto output1 = pt1-pt2;
    bool check = output1.PointAtInfinity();
    if (check){
      std::cout <<"the test passed the check"<<'\n';
    } else {
      std::cout <<"the test did not pass the check"<<'\n';
    }

    return nullptr;
  }
};


#endif  // EXAMPLE_PARTY_H
