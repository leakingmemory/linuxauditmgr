#include <catch2/catch_all.hpp>

#include <filesystem>
#include <fstream>

#include "AppArmorParser.h"
#include "AppArmorValidator.h"

using namespace apparmor;

namespace {
std::filesystem::path makeDir() {
    auto dir = std::filesystem::temp_directory_path() /
               ("aaval_" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}
void write(const std::filesystem::path& p, const std::string& c) {
    std::ofstream(p) << c;
}
} // namespace

TEST_CASE("listProfileFiles skips non-profiles and subdirectories") {
    auto dir = makeDir();
    write(dir / "good.profile", "profile g {\n}\n");
    write(dir / "README", "not a profile\n");
    write(dir / "backup~", "junk\n");
    std::filesystem::create_directories(dir / "abstractions");
    write(dir / "abstractions" / "base", "junk\n");

    auto files = listProfileFiles(dir.string());
    REQUIRE(files.size() == 1);
    CHECK(std::filesystem::path(files[0]).filename() == "good.profile");

    std::filesystem::remove_all(dir);
}

TEST_CASE("validateProfile accepts good profiles and reports bad ones") {
    if (!validatorAvailable()) {
        WARN("apparmor_parser not available; skipping validation checks");
        return;
    }

    auto dir = makeDir();
    const auto good = dir / "good";
    const auto bad = dir / "bad";
    write(good, "profile good /usr/bin/good {\n  /etc/good r,\n}\n");
    // 'zzz' is not a valid permission mode -> apparmor_parser rejects it.
    write(bad, "profile bad /usr/bin/bad {\n  /etc/bad zzz,\n}\n");

    auto rgood = validateProfile(good.string());
    CHECK(rgood.ok);
    CHECK(rgood.output.empty());

    auto rbad = validateProfile(bad.string());
    CHECK_FALSE(rbad.ok);
    CHECK_FALSE(rbad.output.empty());

    std::filesystem::remove_all(dir);
}
