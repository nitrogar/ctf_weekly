#include <array>
#include <cstddef>
#include <iostream>
#include <boost/algorithm/hex.hpp>


int main(int argc, char ** argv){
  std::array<std::byte, 16> p0{};
  std::array<std::byte, 16> p1{};
  std::array<std::byte, 16> p2{};
  std::array<std::byte, 16> c0{};
  std::array<std::byte, 16> c1{};
  std::array<std::byte, 16> c2{};

  boost::algorithm::unhex("", p0.begin());
  boost::algorithm::unhex("", p1.begin());
  boost::algorithm::unhex("", p2.begin());
  boost::algorithm::unhex("", c0.begin());
  boost::algorithm::unhex("", c1.begin());
  boost::algorithm::unhex("", c2.begin());

  return 0;
}
