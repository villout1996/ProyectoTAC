#include <scl/net/config.h>
#include <scl/net/network.h>
#include <scl/net/tcp_channel.h>
#include <scl/protocol/base.h>
#include <scl/util/cmdline.h>

#include "Schnorr.h"

using namespace scl;

void RealNetworkExecution(const util::ProgramOptions& opts) {

  // Get the ID of this party and the network config filename that was passed to
  // the program on the commandline.
  auto id = opts.Get<std::size_t>("id");
  auto sk = opts.Get<std::size_t>("sk");
  auto conf = opts.Get("conf");

  // Create a NetworkConfig object from the file.
  auto network_conf = net::NetworkConfig::Load(id, std::string(conf));

  // Create a network. This takes care of connecting all the parties to each
  // other, using the information in the network config.
  auto network = net::Network::Create<net::TcpChannel<>>(network_conf);

  // Evaluate the protocol for 5 rounds.
  if (id == 0)
    {
      proto::Evaluate(Prover::Create(sk), network);
  }
  if (id == 1)
    {
      proto::Evaluate(Verifier::Create(), network);
  }  
}

int main(int argc, char** argv) {
  // This adds some command line arguments to our program, of which there are
  // only two :)
  const auto opts =
      util::ProgramOptions::Parser{}
          .Add(util::ProgramArg::Required("id", "int", "ID of this party"))
          .Add(util::ProgramArg::Required("sk", "int", "Secret key"))    
          .Add(util::ProgramArg::Required("conf", "string", "network config"))
          .Parse(argc, argv);

  RealNetworkExecution(opts);
}
