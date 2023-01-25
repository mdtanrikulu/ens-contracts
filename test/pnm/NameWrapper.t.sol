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

// Invariant 1:  ownership of root domains
// Invariant 2:  ownership of root domains in wrapper after wrap
// Invariant 3:  resolver address of wrapped name
// Invariant 4:  fuses of frozen 2LD

contract NameWrapperTest is PTest {
    NameWrapper public wrapper;
    ENSRegistry public registry;
    StaticMetadataService public metadata;
    IETHRegistrarController public controller;
    BaseRegistrarImplementation public baseRegistrar;

    address alice;
    address bob;
    address agent;

    address EMPTY_ADDRESS = 0x0000000000000000000000000000000000000000;
    bytes32 ROOT_NODE =
        0x0000000000000000000000000000000000000000000000000000000000000000;
    uint256 CONTRACT_INIT_TIMESTAMP = 7776000 + 90 + 1;

    event NameWrapped(
        bytes32 indexed node,
        bytes name,
        address owner,
        uint32 fuses,
        uint64 expiry
    );

    function setUp() public {
	alice = makeAddr("Alice");
	bob = makeAddr("Bob");

        // warp beyond expire + grace period
        vm.warp(CONTRACT_INIT_TIMESTAMP);

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
        assertEq(registry.resolver(xyzNamehash), bob);
    }

    function testSubdomainExtendAfter2LDExpired(uint64 timestamp) external {
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

        vm.expectRevert();
        wrapper.renew(uint256(testnameNamehash), 86400);

        vm.expectRevert(bytes("ERC1155: insufficient balance for transfer"));
        wrapper.safeTransferFrom(alice, bob, uint256(testnameNamehash), 1, "");

        assertEq(wrapper.ownerOf(uint256(testnameNamehash)), EMPTY_ADDRESS);
    }

    function invariantSubdomainExtendAfter2LDExpired() external view {
        string memory parentLabel = "testname";
        string memory name = string(abi.encodePacked(parentLabel, ".eth"));
        (, bytes32 testnameNamehash) = NameEncoder.dnsEncodeName(name);
        assert(wrapper.ownerOf(uint256(testnameNamehash)) == EMPTY_ADDRESS);
    }

    function testWrappedChildExpired(uint16 childFuse, uint64 timestamp) public {
        vm.assume(
            (isPowerOfTwo(childFuse) && childFuse <= 32) ||
                childFuse == PARENT_CANNOT_CONTROL ||
                childFuse == PARENT_CONTROLLED_FUSES ||
                childFuse == USER_SETTABLE_FUSES
        );
        vm.assume(timestamp > CONTRACT_INIT_TIMESTAMP); // from setup warp

        string memory parentLabel = "testname";
        string memory childLabel = "sub";
        string memory name = string(abi.encodePacked(parentLabel, ".eth"));
        (, bytes32 parentNode) = NameEncoder.dnsEncodeName(name);

        setupState(
            parentNode,
            parentLabel,
            childLabel,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | childFuse,
            timestamp
        );

        (, bytes32 childNode) = NameEncoder.dnsEncodeName(
            string(abi.encodePacked(childLabel, ".", name))
        );

        ownerIsOwner(childNode, bob);
        ownerResetsToZeroWhenExpired(
            childNode,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | childFuse
        );
    }

    function invariantTestWrappedChildExpired() public {
        string memory parentLabel = "testname";
        string memory childLabel = "sub";
        string memory name = string(abi.encodePacked(parentLabel, ".eth"));
        (, bytes32 childNode) = NameEncoder.dnsEncodeName(
            string(abi.encodePacked(childLabel, ".", name))
        );
        ownerIsOwner(childNode, EMPTY_ADDRESS);
    }

    // function invariantEmitWrapEvent() public {
    //     string memory parentLabel = "testname";
    //     string memory childLabel = "sub2";
    //     string memory name = string(abi.encodePacked(parentLabel, ".eth"));
    //     (, bytes32 parentNode) = NameEncoder.dnsEncodeName(name);

    //     vm.expectEmit(true, true, false, true);
    //     emit NameWrapped(parentNode, bytes(name), alice, 0, 84600);

    //     setupState(
    //         parentNode,
    //         parentLabel,
    //         childLabel,
    //         0,
    //         0,
    //         0
    //     );
    // }

    function testWrap_CANNOT_BURN(uint32 parentFuse, uint32 childFuse) public {
        vm.assume(
            (isPowerOfTwo(parentFuse) && parentFuse <= 32)
        );
        vm.assume(
            (isPowerOfTwo(childFuse) && childFuse <= 32)
        );
        string memory parentLabel = "testname";
        string memory childLabel = "sub5";
        string memory name = string(abi.encodePacked(parentLabel, ".eth"));
        (, bytes32 parentNode) = NameEncoder.dnsEncodeName(name);
        (, bytes32 childNode) = NameEncoder.dnsEncodeName(
            string(abi.encodePacked(childLabel, ".", name))
        );

        setupState(
            parentNode,
            parentLabel,
            childLabel,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | CANNOT_BURN_FUSES,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | CANNOT_BURN_FUSES,
            uint64(CONTRACT_INIT_TIMESTAMP) + 86400
        );

        vm.warp(CONTRACT_INIT_TIMESTAMP + 1);

        (, uint32 parentFusesBefore,) = wrapper
            .getData(uint256(parentNode));
        assertEq(parentFusesBefore, PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | CANNOT_BURN_FUSES | IS_DOT_ETH);

        vm.expectRevert();
        wrapper.setFuses(parentNode, uint16(parentFuse));

        (, uint32 parentFusesAfter,) = wrapper
            .getData(uint256(parentNode));
        assertEq(parentFusesAfter, PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | CANNOT_BURN_FUSES | IS_DOT_ETH);
        
        (, uint32 childFusesBefore,) = wrapper
            .getData(uint256(childNode));
        assertEq(childFusesBefore, PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | CANNOT_BURN_FUSES);

        vm.expectRevert();
        wrapper.setFuses(childNode, uint16(childFuse));

        (, uint32 childFusesAfter,) = wrapper
            .getData(uint256(childNode));
        assertEq(childFusesAfter, PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | CANNOT_BURN_FUSES);
    }

    function ownerIsOwner(bytes32 childNode, address owner) private {
        (, uint32 expiry, ) = wrapper.getData(uint256(childNode));
        assertLt(expiry, block.timestamp);
        assertEq(wrapper.ownerOf(uint256(childNode)), owner);
    }

    function ownerResetsToZeroWhenExpired(bytes32 childNode, uint32 fuses)
        private
    {
        (address ownerBefore, uint32 fusesBefore, uint64 expiryBefore) = wrapper
            .getData(uint256(childNode));
        assertEq(ownerBefore, bob);

        // not expired
        assertGe(expiryBefore, block.timestamp);
        assertEq(fusesBefore, fuses);
        // force expiry
        vm.warp(expiryBefore + 1);
        (address ownerAfter, uint32 fusesAfter, uint64 expiryAfter) = wrapper
            .getData(uint256(childNode));

        // owner and fuses are reset when expired
        assertEq(ownerAfter, EMPTY_ADDRESS);
        assertLt(expiryAfter, block.timestamp);
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
}
