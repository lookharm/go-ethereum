// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

contract Test {
    int256 public A = 1;

    function SetA(int256 a) public {
        A = a;
    }
}