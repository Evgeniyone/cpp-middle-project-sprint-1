#include "cmd_options.h"

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) { return false; }

}  // namespace CryptoGuard
