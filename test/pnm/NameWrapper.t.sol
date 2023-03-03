// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../contracts/registry/ENSRegistry.sol";
import "../../contracts/ethregistrar/BaseRegistrarImplementation.sol";
import "../../contracts/ethregistrar/DummyOracle.sol";
import "../../contracts/wrapper/StaticMetadataService.sol";
import "../../contracts/wrapper/IMetadataService.sol";
import "../../contracts/wrapper/NameWrapper.sol";

import {IncompatibleParent, IncorrectTargetOwner, OperationProhibited, Unauthorised} from "../../contracts/wrapper/NameWrapper.sol";
import {CANNOT_UNWRAP, CANNOT_BURN_FUSES, CANNOT_TRANSFER, CANNOT_SET_RESOLVER, CANNOT_SET_TTL, CANNOT_CREATE_SUBDOMAIN, PARENT_CANNOT_CONTROL, CAN_DO_EVERYTHING} from "../../contracts/wrapper/INameWrapper.sol";
import {NameEncoder} from "../../contracts/utils/NameEncoder.sol";
import {ReverseRegistrar} from "../../contracts/registry/ReverseRegistrar.sol";
import {AggregatorInterface, StablePriceOracle} from "../../contracts/ethregistrar/StablePriceOracle.sol";
import {ETHRegistrarController, IETHRegistrarController} from "../../contracts/ethregistrar/ETHRegistrarController.sol";

import {PTest} from "@pwnednomore/contracts/PTest.sol";

// Invariant 1:  ownership of root domains
// Invariant 2:  ownership of root domains in wrapper after wrap
// Invariant 3:  allow change of resolver address
// Invariant 4:  fuses of frozen 2LD
// Invariant 5:  allow change of metadata service

contract NameWrapperTest is PTest {
    NameWrapper public wrapper;
    ENSRegistry public registry;
    StaticMetadataService public metadata;
    IETHRegistrarController public controller;
    BaseRegistrarImplementation public baseRegistrar;

    address alice;
    address bob;
    address agent;

    address MOCK_RESOLVER = 0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41;
    address EMPTY_ADDRESS = 0x0000000000000000000000000000000000000000;
    bytes32 ROOT_NODE =
        0x0000000000000000000000000000000000000000000000000000000000000000;
    uint256 CONTRACT_INIT_TIMESTAMP = 90 days;

    // ### EVENTS

    event NameWrapped(
        bytes32 indexed node,
        bytes name,
        address owner,
        uint32 fuses,
        uint64 expiry
    );

    event FusesSet(bytes32 indexed node, uint32 fuses, uint64 expiry);

    // ### EVENTS

    function setUp() public {
        alice = makeAddr("Alice");
        bob = makeAddr("Bob");

        vm.startPrank(alice);

        // warp beyond expire + grace period
        vm.warp(CONTRACT_INIT_TIMESTAMP + 1);

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

        baseRegistrar.addController(address(wrapper));
        baseRegistrar.addController(alice);
        wrapper.setController(alice, true);

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

    function invariantOwnershipTLD() public {
        (, bytes32 ethNamehash) = NameEncoder.dnsEncodeName("eth");
        assertEq(wrapper.ownerOf(uint256(ethNamehash)), EMPTY_ADDRESS);
    }

    function invariantWrapTLD() public {
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

    function invariantUnwrapTLD() public {
        (bytes memory encodedName, bytes32 xyzNamehash) = NameEncoder
            .dnsEncodeName("xyz");
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), EMPTY_ADDRESS);
        registry.setApprovalForAll(address(wrapper), true);
        wrapper.wrap(encodedName, alice, EMPTY_ADDRESS);
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), alice);
        wrapper.unwrap(ROOT_NODE, keccak256("xyz"), alice);
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), EMPTY_ADDRESS);
    }

    function invariantAllowMetadataService() public {
        metadata = new StaticMetadataService("https://metadata.ens.domains");
        IMetadataService ms = IMetadataService(address(metadata));
        wrapper.setMetadataService(ms);
        assertEq(address(wrapper.metadataService()), address(metadata));
    }

    function testSubdomainExtendAfter2LDExpired(uint64 timestamp) external {
        // Subdomain should not be extendible and transferable if parent domain is expired.
        vm.assume(timestamp > block.timestamp + 90 days + 86400);
        string memory parentLabel = "testname";
        string memory childLabel = "sub";
        uint256 labelHash = uint256(labelhash(parentLabel));
        bytes32 testnameNamehash = namehash(parentLabel);

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

        vm.warp(timestamp);

        vm.expectRevert(); // cannot renew if expired
        wrapper.renew(uint256(testnameNamehash), 86400);

        vm.expectRevert(bytes("ERC1155: insufficient balance for transfer"));
        wrapper.safeTransferFrom(alice, bob, uint256(testnameNamehash), 1, "");

        assertEq(wrapper.ownerOf(uint256(testnameNamehash)), EMPTY_ADDRESS);
    }

    function testWrappedChildExpired(
        uint16 parentFuse,
        uint16 childFuse,
        uint64 timestamp
    ) public {
        // subdomain owner should be reset to zero when expired
        vm.assume(filterFuses(parentFuse)); // CANNOT_CREATE_SUBDOMAIN
        vm.assume(filterFuses(childFuse));
        vm.assume(timestamp > CONTRACT_INIT_TIMESTAMP); // from setup warp

        string memory parentLabel = "testname";
        string memory childLabel = "sub";
        string memory name = string(abi.encodePacked(parentLabel, ".eth"));
        bytes32 parentNode = namehash(parentLabel);

        if ((parentFuse == 0 && childFuse == 0)) return;

        if (fuseForbidden(parentFuse, CANNOT_CREATE_SUBDOMAIN)) {
            assertEq(
                baseRegistrar.available(uint256(labelhash(parentLabel))),
                true
            );
            baseRegistrar.register(
                uint256(labelhash(parentLabel)),
                alice,
                84600
            );
            assertEq(
                baseRegistrar.ownerOf(uint256(labelhash(parentLabel))),
                address(alice)
            );
            wrapper.wrapETH2LD(
                parentLabel,
                alice,
                uint16(parentFuse),
                EMPTY_ADDRESS
            );
            vm.expectRevert(
                abi.encodeWithSelector(OperationProhibited.selector, parentNode)
            );
            wrapper.setSubnodeOwner(
                parentNode,
                childLabel,
                bob,
                childFuse,
                timestamp
            );
            return;
        }

        vm.expectEmit(true, true, false, false);
        emit NameWrapped(parentNode, bytes(name), alice, parentFuse, timestamp);

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

        ownerIsOwner(childNode, bob);
        ownerResetsToZeroWhenExpired(childNode, childFuse);
    }

    function testWrap_CANNOT_BURN(uint32 parentFuse, uint32 childFuse) public {
        // should not burn fuses any more if CANNOT_BURN fuse is burnt
        vm.assume((isPowerOfTwo(parentFuse) && parentFuse <= 32));
        vm.assume((isPowerOfTwo(childFuse) && childFuse <= 32));
        string memory parentLabel = "testname";
        string memory childLabel = "sub5";
        bytes32 parentNode = namehash(parentLabel);
        bytes32 childNode = namehash(
            string(abi.encodePacked(childLabel, ".", parentLabel))
        );

        setupState(
            parentNode,
            parentLabel,
            childLabel,
            CANNOT_UNWRAP | CANNOT_BURN_FUSES,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | CANNOT_BURN_FUSES,
            uint64(CONTRACT_INIT_TIMESTAMP) + 86400
        );

        vm.warp(CONTRACT_INIT_TIMESTAMP);

        (, uint32 parentFusesBefore, ) = wrapper.getData(uint256(parentNode));
        assertEq(
            parentFusesBefore,
            PARENT_CANNOT_CONTROL |
                CANNOT_UNWRAP |
                CANNOT_BURN_FUSES |
                IS_DOT_ETH
        );

        vm.expectRevert();
        wrapper.setFuses(parentNode, uint16(parentFuse));

        (, uint32 parentFusesAfter, ) = wrapper.getData(uint256(parentNode));
        assertEq(
            parentFusesAfter,
            PARENT_CANNOT_CONTROL |
                CANNOT_UNWRAP |
                CANNOT_BURN_FUSES |
                IS_DOT_ETH
        );

        (, uint32 childFusesBefore, ) = wrapper.getData(uint256(childNode));
        assertEq(
            childFusesBefore,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | CANNOT_BURN_FUSES
        );

        vm.expectRevert();
        wrapper.setFuses(childNode, uint16(childFuse));

        (, uint32 childFusesAfter, ) = wrapper.getData(uint256(childNode));
        assertEq(
            childFusesAfter,
            PARENT_CANNOT_CONTROL | CANNOT_UNWRAP | CANNOT_BURN_FUSES
        );
    }

    function testWrapUnwrap() external {
        string memory label = "wrapunwrap";
        (bytes memory encodedNameETH, bytes32 ensNamehash) = NameEncoder
            .dnsEncodeName("wrapunwrap.eth");
        (bytes memory encodedNameXYZ, bytes32 xyzNamehash) = NameEncoder
            .dnsEncodeName("xyz");
        (
            bytes memory encodedNameWrapUnwrapXYZ,
            bytes32 wrapUnwrapXYZNamehash
        ) = NameEncoder.dnsEncodeName("wrapunwrap.xyz");

        registry.setApprovalForAll(address(wrapper), true);

        assertEq(wrapper.ownerOf(uint256(ensNamehash)), EMPTY_ADDRESS);

        vm.expectRevert(IncompatibleParent.selector);
        wrapper.wrap(encodedNameETH, alice, EMPTY_ADDRESS);

        assertEq(
            wrapper.ownerOf(uint256(wrapUnwrapXYZNamehash)),
            EMPTY_ADDRESS
        );

        registry.setSubnodeOwner(xyzNamehash, labelhash(label), alice);

        vm.stopPrank();
        vm.startPrank(bob);

        vm.expectRevert(
            abi.encodeWithSelector(
                Unauthorised.selector,
                wrapUnwrapXYZNamehash,
                address(bob)
            )
        );
        wrapper.wrap(encodedNameWrapUnwrapXYZ, alice, EMPTY_ADDRESS);

        vm.stopPrank();
        vm.startPrank(alice);

        wrapper.wrap(encodedNameWrapUnwrapXYZ, alice, MOCK_RESOLVER);
        assertEq(wrapper.ownerOf(uint256(wrapUnwrapXYZNamehash)), alice);

        vm.expectRevert(
            abi.encodeWithSelector(
                IncorrectTargetOwner.selector,
                address(wrapper)
            )
        );
        wrapper.unwrap(xyzNamehash, labelhash(label), address(wrapper));

        wrapper.unwrap(xyzNamehash, labelhash(label), alice);
        assertEq(wrapper.ownerOf(uint256(xyzNamehash)), EMPTY_ADDRESS);
    }

    function testWrapUnwrapENS2LD() external {
        string memory parentLabel = "wrapunwrapens2ld";
        bytes32 labelHash = labelhash(parentLabel);
        bytes32 testnameNamehash = namehash(parentLabel);

        // to be able to use setSubnode record parent name fuse should be
        // either in CAN_DO_EVERYTHING state (child too in this case) or PARENT_CANNOT_CONTROL | CANNOT_UNWRAP
        wrapper.registerAndWrapETH2LD(
            parentLabel,
            alice,
            86400,
            EMPTY_ADDRESS,
            0
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IncorrectTargetOwner.selector,
                address(wrapper)
            )
        );
        wrapper.unwrapETH2LD(labelHash, address(wrapper), address(wrapper));

        wrapper.unwrapETH2LD(labelHash, alice, alice);
        assertEq(wrapper.ownerOf(uint256(testnameNamehash)), EMPTY_ADDRESS);
    }

    function testSetChildFuses(
        uint16 parentFuse,
        uint16 childFuse,
        uint64 timestamp
    ) external {
        vm.assume(filterFuses(parentFuse));
        vm.assume(filterFuses(childFuse));
        vm.assume(timestamp > CONTRACT_INIT_TIMESTAMP);

        string memory parentLabel = "childfusestest";
        string memory childLabel = "set";
        uint256 parentLabelHash = uint256(labelhash(parentLabel));
        uint256 childLabelHash = uint256(labelhash(childLabel));
        bytes32 tokenId = namehash(parentLabel);
        bytes32 subTokenId = namehash(
            string(abi.encodePacked(childLabel, ".", parentLabel))
        );

        setupState(
            tokenId,
            parentLabel,
            childLabel,
            parentFuse == 0 ? parentFuse : (CANNOT_UNWRAP | parentFuse),
            CAN_DO_EVERYTHING,
            0
        );

        wrapper.setChildFuses(
            tokenId,
            bytes32(childLabelHash),
            childFuse,
            timestamp
        );
        (, uint32 fuses, ) = wrapper.getData(uint256(subTokenId));
        assertEq(fuses, childFuse);
    }

    function testSetSubdomainRecord(
        uint16 parentFuse,
        uint16 childFuse,
        uint64 timestamp
    ) external {
        // Subdomain should not be transferable if parent domain is expired.
        vm.assume(
            filterFuses(
                parentFuse
                // filter out CANNOT_SET_TTL, CANNOT_SET_RESOLVER and CANNOT_CREATE_SUBDOMAIN
            )
        );
        vm.assume(filterFuses(childFuse));
        vm.assume(timestamp > CONTRACT_INIT_TIMESTAMP);
        string memory parentLabel = "testrecord";
        string memory childLabel = "subrecord";
        uint256 labelHash = uint256(labelhash(parentLabel));
        bytes32 testnameNamehash = namehash(parentLabel);
        bytes32 testsubnameNamehash = namehash(
            string(abi.encodePacked(childLabel, ".", parentLabel))
        );

        // to be able to use setSubnode record parent name fuse should be
        // either in CAN_DO_EVERYTHING state (child too in this case) or PARENT_CANNOT_CONTROL | CANNOT_UNWRAP
        if (
            !(parentFuse == 0 && childFuse == 0) &&
            fuseForbidden(
                parentFuse,
                CANNOT_CREATE_SUBDOMAIN | CANNOT_SET_RESOLVER | CANNOT_SET_TTL
            )
        ) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    OperationProhibited.selector,
                    testnameNamehash
                )
            );
            wrapper.registerAndWrapETH2LD(
                parentLabel,
                alice,
                86400,
                EMPTY_ADDRESS,
                parentFuse
            );
            return;
        }

        wrapper.registerAndWrapETH2LD(
            parentLabel,
            alice,
            86400,
            EMPTY_ADDRESS,
            parentFuse
        );
        wrapper.setSubnodeRecord(
            testnameNamehash,
            childLabel,
            alice,
            EMPTY_ADDRESS,
            timestamp,
            childFuse,
            timestamp
        );

        assertEq(wrapper.ownerOf(uint256(testsubnameNamehash)), alice);

        wrapper.setSubnodeRecord(
            testnameNamehash,
            childLabel,
            alice,
            MOCK_RESOLVER,
            timestamp,
            childFuse,
            timestamp
        );
    }

    function testSetResolver(uint32 parentFuse, uint64 timestamp) public {
        vm.assume(filterFuses(parentFuse));
        vm.assume(
            timestamp > CONTRACT_INIT_TIMESTAMP &&
                timestamp <= type(uint64).max - CONTRACT_INIT_TIMESTAMP
        );

        string memory label = "resolvertest";
        bytes32 tokenId = namehash(label);

        registerSetupAndWrapName(label, alice, parentFuse, timestamp);

        if (parentFuse != 0 && fuseForbidden(parentFuse, CANNOT_SET_RESOLVER)) {
            vm.expectRevert(
                abi.encodeWithSelector(OperationProhibited.selector, tokenId)
            );
            wrapper.setResolver(tokenId, MOCK_RESOLVER);
            return;
        }

        wrapper.setResolver(tokenId, MOCK_RESOLVER);
        assertEq(registry.resolver(tokenId), MOCK_RESOLVER);
    }

    function testSetTTL(
        uint32 parentFuse,
        uint64 timestamp,
        uint64 ttl
    ) public {
        vm.assume(
            // filter out CANNOT_SET_TTL
            filterFuses(parentFuse)
        );

        vm.assume(
            timestamp > CONTRACT_INIT_TIMESTAMP &&
                timestamp <= type(uint64).max - CONTRACT_INIT_TIMESTAMP
            // more than given amount will cause aritmethic overflow under _wrapETH2LD
        );

        vm.assume(ttl < type(uint64).max);

        string memory label = "ttltest";
        bytes32 tokenId = namehash(label);

        registerSetupAndWrapName(label, alice, parentFuse, timestamp);
        if ((parentFuse != 0) && fuseForbidden(parentFuse, CANNOT_SET_TTL)) {
            vm.expectRevert(
                abi.encodeWithSelector(OperationProhibited.selector, tokenId)
            );
            wrapper.setTTL(tokenId, ttl);
            return;
        }
        wrapper.setTTL(tokenId, ttl);
    }

    function testSetRecord(uint32 parentFuse, uint64 timestamp) public {
        vm.assume(filterFuses(parentFuse));
        vm.assume(
            timestamp > CONTRACT_INIT_TIMESTAMP &&
                timestamp <= type(uint64).max - CONTRACT_INIT_TIMESTAMP
        );

        string memory label = "recordtest";
        bytes32 tokenId = namehash(label);

        registerSetupAndWrapName(label, alice, parentFuse, timestamp);

        if (
            (parentFuse != 0) &&
            fuseForbidden(parentFuse, CANNOT_BURN_FUSES | CANNOT_SET_RESOLVER | CANNOT_SET_TTL)
        ) {
            vm.expectRevert(
                abi.encodeWithSelector(OperationProhibited.selector, tokenId)
            );
            wrapper.setRecord(tokenId, bob, MOCK_RESOLVER, timestamp);
            return;
        }

        vm.expectRevert(
            abi.encodeWithSelector(IncorrectTargetOwner.selector, EMPTY_ADDRESS)
        );
        wrapper.setRecord(tokenId, EMPTY_ADDRESS, MOCK_RESOLVER, timestamp);

        wrapper.setRecord(tokenId, bob, MOCK_RESOLVER, timestamp);
    }

    function testSetFuses(uint32 parentFuse, uint64 timestamp) public {
        vm.assume(
            // filter out CANNOT_BURN_FUSES
            filterFuses(parentFuse)
        );
        vm.assume(
            timestamp > block.timestamp &&
                timestamp <= type(uint64).max - (CONTRACT_INIT_TIMESTAMP + block.timestamp)
                // duration + block.timestamp applies under ens._register
                // GRACE_PERIOD applies under wrapper._wrapETH2LD
        );

        string memory label = "fusetest";
        bytes32 tokenId = namehash(label);

        registerSetupAndWrapName(label, alice, parentFuse, timestamp);

        if (fuseForbidden(parentFuse, CANNOT_BURN_FUSES)) {
            vm.expectRevert(
                abi.encodeWithSelector(OperationProhibited.selector, tokenId)
            );
            wrapper.setFuses(tokenId, uint16(CANNOT_SET_TTL));
            return;
        }

        wrapper.setFuses(tokenId, uint16(CANNOT_SET_TTL));
        (, uint32 fuses, ) = wrapper.getData(uint256(tokenId));
        assertEq(
            fuses,
            PARENT_CANNOT_CONTROL | parentFuse | CANNOT_SET_TTL | IS_DOT_ETH
        );
    }

    // control methods

    function ownerIsOwner(bytes32 childNode, address owner) private {
        (, , uint64 expiry) = wrapper.getData(uint256(childNode));
        assertGe(expiry, block.timestamp);
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

    // utility methods

    function namehash(string memory label) private pure returns (bytes32) {
        string memory name = string(abi.encodePacked(label, ".eth"));
        (, bytes32 testnameNamehash) = NameEncoder.dnsEncodeName(name);
        return testnameNamehash;
    }

    function labelhash(string memory label) private pure returns (bytes32) {
        return keccak256(bytes(label));
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

    function registerSetupAndWrapName(
        string memory label,
        address account,
        uint32 fuses,
        uint64 expiry
    ) private {
        bytes32 tokenId = labelhash(label);

        baseRegistrar.register(uint256(tokenId), account, expiry);
        baseRegistrar.setApprovalForAll(address(wrapper), true);

        wrapper.wrapETH2LD(label, account, uint16(fuses), EMPTY_ADDRESS);
    }

    function fuseForbidden(uint32 fuse, uint32 filter) private returns (bool) {
        return (fuse & filter > 0 || fuse & CANNOT_UNWRAP == 0);
    }

    function filterFuses(uint32 fuses) private returns (bool) {
        if (fuses == 0) return true;
        if ((fuses & CANNOT_UNWRAP) == 0) return false;

        uint32 diff = fuses ^ (1 | (1 << 16));

        uint32[5] memory fuseDict = [
            CANNOT_CREATE_SUBDOMAIN,
            CANNOT_SET_TTL,
            CANNOT_SET_RESOLVER,
            CANNOT_TRANSFER,
            CANNOT_BURN_FUSES
        ];

        for (uint256 i = 0; i < fuseDict.length; i++) {
            if (diff == 0) break;
            uint32 fuse = fuseDict[i];
            if (diff >= fuse) diff = diff ^ fuse;
        }
        return diff == 0;
    }
}
