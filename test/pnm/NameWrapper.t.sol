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

        wrapper.setController(alice, true);
        baseRegistrar.addController(alice);

        vm.startPrank(alice);
        baseRegistrar.setApprovalForAll(address(wrapper), true);

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

    function invariantOwnership() public {
        (, bytes32 ethNamehash) = NameEncoder.dnsEncodeName("eth");
        assertEq(wrapper.ownerOf(uint256(ethNamehash)), EMPTY_ADDRESS);
    }

    function invariantWrap() public {
        (bytes memory encodedName, bytes32 xyzNamehash) = NameEncoder
            .dnsEncodeName("xyz");
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), EMPTY_ADDRESS);
        registry.setApprovalForAll(address(wrapper), true);
        wrapper.wrap(encodedName, alice, EMPTY_ADDRESS);
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), alice);
    }

    function invariantAllowResolver() public {
        (bytes memory encodedName, bytes32 xyzNamehash) = NameEncoder
            .dnsEncodeName("xyz");
        registry.setApprovalForAll(address(wrapper), true);
        wrapper.wrap(encodedName, alice, bob);
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), alice);
    }

    function testSubdomainExtendAfter2LDExpired(uint64 timestamp) external {
        // Invariant:
        // Subdomain should not be transferable if parent domain is expired.
        vm.assume(timestamp > block.timestamp + 63113904);
        string memory parentLabel = "testname";
        string memory childLabel = "sub";
        uint256 labelHash = uint256(labelhash(parentLabel));
        string memory name = string(abi.encodePacked(parentLabel, ".eth"));
        (, bytes32 testnameNamehash) = NameEncoder.dnsEncodeName(name);

        setupState(
            testnameNamehash,
            parentLabel,
            childLabel,
            CAN_DO_EVERYTHING,
            CAN_DO_EVERYTHING,
            0
        );

        assertEq(baseRegistrar.ownerOf(labelHash), address(wrapper));
        assertEq(wrapper.ownerOf(uint256(testnameNamehash)), alice);
        // vm.warp(block.timestamp + 63113904);
        vm.warp(timestamp);
        wrapper.safeTransferFrom(alice, bob, uint256(testnameNamehash), 1, "");
    }

    function invariantSubdomainExtendAfter2LDExpired() external view {
        // The transfer should not happen to Bob if expired
        string memory parentLabel = "testname";
        string memory name = string(abi.encodePacked(parentLabel, ".eth"));
        (, bytes32 testnameNamehash) = NameEncoder.dnsEncodeName(name);
        assert(wrapper.ownerOf(uint256(testnameNamehash)) == EMPTY_ADDRESS);
    }

    function testWrappedExpired(
        uint16 parentFuse,
        uint16 childFuse,
        uint64 timestamp
    ) public {
        vm.assume(isPowerOfTwo(parentFuse) && parentFuse <= 64);
        vm.assume(isPowerOfTwo(childFuse) && childFuse <= 64);
        vm.assume(timestamp >= 0);

        string memory parentLabel = "testname";
        string memory childLabel = "sub";
        string memory name = string(abi.encodePacked(parentLabel, ".eth"));
        (, bytes32 parentNode) = NameEncoder.dnsEncodeName(name);

        setupState(
            parentNode,
            parentLabel,
            childLabel,
            parentFuse,
            childFuse,
            timestamp
        );

        (, bytes32 childNode) = NameEncoder.dnsEncodeName(
            string(abi.encodePacked(childLabel, ".", name))
        );
        ownerIsOwnerWhenExpired(childNode);
    }

    function invariantTestWrappedExpired() public {
        string memory parentLabel = "testname";
        string memory childLabel = "sub";
        string memory name = string(abi.encodePacked(parentLabel, ".eth"));
        (, bytes32 childNode) = NameEncoder.dnsEncodeName(
            string(abi.encodePacked(childLabel, ".", name))
        );
        ownerIsOwnerWhenExpired(childNode);
    }

    function ownerIsOwnerWhenExpired(bytes32 childNode) private {
        (, uint32 expiry, ) = wrapper.getData(uint256(childNode));
        assertLt(expiry, block.timestamp);
        assertEq(wrapper.ownerOf(uint256(childNode)), bob);
    }

    function ownerResetsToZeroWhenExpired(bytes32 childNode, uint32 fuses)
        private
    {
        (address ownerBefore, uint32 fusesBefore, uint64 expiryBefore) = wrapper
            .getData(uint256(childNode));
        assertEq(ownerBefore, bob);

        // not expired
        assertEq(expiryBefore, block.timestamp);
        assertEq(fusesBefore, fuses);
        // force expiry
        vm.warp(84600 * 2);
        (address ownerAfter, uint32 fusesAfter, uint64 expiryAfter) = wrapper
            .getData(uint256(childNode));

        // owner and fuses are reset when expired
        assertEq(ownerAfter, EMPTY_ADDRESS);
        assertEq(expiryAfter, block.timestamp);
        assertEq(fusesAfter, 0);
    }

    function labelhash(string memory name) private pure returns (bytes32) {
        return keccak256(bytes(name));
    }

    function isPowerOfTwo(uint256 x) private pure returns (bool) {
        if (x <= 0) return false;
        return (x & (x - 1)) == 0;
    }

    function setupState(
        bytes32 parentNode,
        string memory parentLabel,
        string memory childLabel,
        uint32 parentFuses,
        uint32 childFuses,
        uint64 childExpiry
    ) private {
        assertEq(
            baseRegistrar.available(uint256(labelhash(parentLabel))),
            true
        );
        baseRegistrar.register(uint256(labelhash(parentLabel)), alice, 84600);
        assertEq(
            baseRegistrar.ownerOf(uint256(labelhash(parentLabel))),
            address(alice)
        );
        wrapper.wrapETH2LD(
            parentLabel,
            alice,
            uint16(parentFuses),
            EMPTY_ADDRESS
        );
        wrapper.setSubnodeOwner(
            parentNode,
            childLabel,
            bob,
            childFuses,
            childExpiry
        );
    }

    function setupState0000DW(
        bytes32 parentNode,
        string memory parentLabel,
        string memory childLabel,
        uint16[] memory fuses
    ) private {
        // Expired, nothing burnt.
        setupState(
            parentNode,
            parentLabel,
            childLabel,
            CAN_DO_EVERYTHING,
            CAN_DO_EVERYTHING,
            0
        );
        (, uint32 parentFuses, ) = wrapper.getData(uint256(parentNode));
        assertEq(parentFuses, PARENT_CANNOT_CONTROL | IS_DOT_ETH);
        (, bytes32 childNode) = NameEncoder.dnsEncodeName(
            string(abi.encodePacked(childLabel, ".", parentLabel, ".eth"))
        );
        (, uint32 childFuses, uint64 childExpiry) = wrapper.getData(
            uint256(childNode)
        );
        assertEq(childFuses, CAN_DO_EVERYTHING);
        assertEq(childExpiry, 0);
    }
}
