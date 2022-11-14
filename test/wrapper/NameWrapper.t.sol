// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../contracts/registry/ENSRegistry.sol";
import "../../contracts/ethregistrar/BaseRegistrarImplementation.sol";
import "../../contracts/ethregistrar/DummyOracle.sol";
import "../../contracts/wrapper/StaticMetadataService.sol";
import "../../contracts/wrapper/IMetadataService.sol";
import "../../contracts/wrapper/NameWrapper.sol";

import {PTest} from "@pwnednomore/contracts/PTest.sol";
import {CANNOT_UNWRAP, CANNOT_BURN_FUSES, CANNOT_TRANSFER, CANNOT_SET_RESOLVER, CANNOT_SET_TTL, CANNOT_CREATE_SUBDOMAIN, PARENT_CANNOT_CONTROL, CAN_DO_EVERYTHING} from "../../contracts/wrapper/INameWrapper.sol";
import {NameEncoder} from "../../contracts/utils/NameEncoder.sol";
import {ReverseRegistrar} from "../../contracts/registry/ReverseRegistrar.sol";
import {AggregatorInterface, StablePriceOracle} from "../../contracts/ethregistrar/StablePriceOracle.sol";
import {ETHRegistrarController, IETHRegistrarController} from "../../contracts/ethregistrar/ETHRegistrarController.sol";

contract NameWrapperTest is PTest {
    NameWrapper public wrapper;
    ENSRegistry public registry;
    StaticMetadataService public metadata;
    IETHRegistrarController public controller;
    BaseRegistrarImplementation public baseRegistrar;

    address alice = vm.addr(1);
    address bob = vm.addr(2);
    address agent;

    address EMPTY_ADDRESS = 0x0000000000000000000000000000000000000000;
    bytes32 ROOT_NODE =
        0x0000000000000000000000000000000000000000000000000000000000000000;

    function setUp() public {
        // warp beyond expire + grace period
        vm.warp(7776000 + 90 + 1);
        
        agent = getAgent();
        registry = new ENSRegistry();

        (, bytes32 ethNamehash) = NameEncoder.dnsEncodeName("eth");

        baseRegistrar = new BaseRegistrarImplementation(registry, ethNamehash);
        metadata = new StaticMetadataService("https://ens.domains");
        IMetadataService ms = IMetadataService(address(metadata));
        wrapper = new NameWrapper(registry, baseRegistrar, ms);

        // setup .eth
        registry.setSubnodeOwner(
            ROOT_NODE,
            labelhash("eth"),
            address(baseRegistrar)
        );
        // test if base registrar is the owner of .eth
        assertEq(registry.owner(ethNamehash), address(baseRegistrar));

        // setup .xyz
        registry.setSubnodeOwner(ROOT_NODE, labelhash("xyz"), alice);

        // DummyOracle dummyOracle = new DummyOracle(100000000);
        // AggregatorInterface aggregator = AggregatorInterface(
        //     address(dummyOracle)
        // );

        // uint256[] memory rentPrices = new uint256[](5);
        // uint8[5] memory _prices = [0,0,4,2,1];
        // for(uint256 i=0; i<_prices.length; i++) {
        //     rentPrices[i] = _prices[i];
        // }

        // StablePriceOracle priceOracle = new StablePriceOracle(
        //     aggregator,
        //     rentPrices
        // );
        // ReverseRegistrar reverseRegistrar = new ReverseRegistrar(registry);
        // ETHRegistrarController ensReg = new ETHRegistrarController(
        //     baseRegistrar,
        //     priceOracle,
        //     600,
        //     86400,
        //     reverseRegistrar,
        //     wrapper
        // );

        // controller = IETHRegistrarController(ensReg);
    }

    function testOwnership() public {
        (, bytes32 ethNamehash) = NameEncoder.dnsEncodeName("eth");
        assertEq(wrapper.ownerOf(uint256(ethNamehash)), EMPTY_ADDRESS);
    }

    function testWrap() public {
        vm.startPrank(alice);

        (bytes memory encodedName, bytes32 xyzNamehash) = NameEncoder
            .dnsEncodeName("xyz");
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), EMPTY_ADDRESS);
        registry.setApprovalForAll(address(wrapper), true);
        wrapper.wrap(encodedName, alice, EMPTY_ADDRESS);
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), alice);
    }

    function testAllowResolver() public {
        vm.startPrank(alice);

        (bytes memory encodedName, bytes32 xyzNamehash) = NameEncoder
            .dnsEncodeName("xyz");
        registry.setApprovalForAll(address(wrapper), true);
        wrapper.wrap(encodedName, alice, bob);
        vm.stopPrank();
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), alice);
    }

    function testSubdomainExtendAfter2LDExpired() external {
        // Invariant:
        // Subdomain should not be transferable if parent domain is expired.

        string memory label = "testname";
        string memory sublabel = "sub";
        uint256 labelHash = uint256(labelhash(label));
        string memory name = string(abi.encodePacked(label, ".eth"));

        wrapper.setController(alice, true);
        baseRegistrar.addController(alice);

        vm.startPrank(alice);

        assertEq(baseRegistrar.available(labelHash), true);
        baseRegistrar.register(labelHash, alice, 84600);
        baseRegistrar.setApprovalForAll(address(wrapper), true);
        assertEq(baseRegistrar.ownerOf(labelHash), address(alice));

        wrapper.wrapETH2LD(
            label,
            alice,
            CAN_DO_EVERYTHING,
            86400,
            EMPTY_ADDRESS
        );

        (bytes memory encodedName, bytes32 testnameNamehash) = NameEncoder
            .dnsEncodeName(name);
        wrapper.setSubnodeOwner(
            testnameNamehash,
            sublabel,
            bob,
            CAN_DO_EVERYTHING,
            0
        );

        assertEq(baseRegistrar.ownerOf(labelHash), address(wrapper));
        assertEq(wrapper.ownerOf(uint256(testnameNamehash)), alice);
        vm.warp(block.timestamp +  63113904);
        wrapper.safeTransferFrom(alice, bob, uint256(testnameNamehash), 1, "");
        assertEq(wrapper.ownerOf(uint256(testnameNamehash)), bob);
        vm.stopPrank();
    }

    function labelhash(string memory name) private pure returns (bytes32) {
        return keccak256(bytes(name));
    }
}
