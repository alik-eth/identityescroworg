// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract QKBGroth16VerifierStubRsa {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 7985138272153756164721002236711448137161963857342239923223105247807396096666;
    uint256 constant deltax2 = 7730603868132989197918619068156718242640506531020840617015895657835420861355;
    uint256 constant deltay1 = 6717461534800317000366985306461779300443579779844329258649852050757619017541;
    uint256 constant deltay2 = 9346948889916440755057795466142763651777564690664042652684210023983295388013;

    
    uint256 constant IC0x = 13524669417078712507932147568303035209649694876453310536175516381784219766032;
    uint256 constant IC0y = 12184010309488625096544115668867520302095303397612627685847616508503355526163;
    
    uint256 constant IC1x = 5249614895925269884591856479421978176605667176228011570236263041839848939446;
    uint256 constant IC1y = 19314104857122318104157362529773747942042262013563923384197220514425658598417;
    
    uint256 constant IC2x = 1334859838111890064464075510269443606800897685877532617221351819735443832162;
    uint256 constant IC2y = 19269953181834366673873862575960173564017427512860509747861688253904070264082;
    
    uint256 constant IC3x = 5755570659332223314147764238161615869104231284465646854730554199573958514662;
    uint256 constant IC3y = 20876710993091770453279366807139860253819594664491833393973503917118856735844;
    
    uint256 constant IC4x = 2056257974824891743208458778516702109108379909102701627883767818093121087617;
    uint256 constant IC4y = 9176486723213928818882289466159653836154549224180457018555672871277212575415;
    
    uint256 constant IC5x = 14767443434557794840885626964056650510179253978353522904365064853232464950255;
    uint256 constant IC5y = 501067669039122549413604916394417961019951160221341629486393695000219417918;
    
    uint256 constant IC6x = 18641630313784086136409815527559823514251006961121469070684895578227915529676;
    uint256 constant IC6y = 9578511194801043428803603839158199423122781619309758188311678516784106619827;
    
    uint256 constant IC7x = 9331877304373136263002833859586887435315565447584388144445187202899074051891;
    uint256 constant IC7y = 9637078059017432857282762637222231331807031021040695911583828387853631776221;
    
    uint256 constant IC8x = 19105836872486516911021655485941704124896230102592318460302755208004245946530;
    uint256 constant IC8y = 17937213871941395215283973900493126403686901599955953220039132605917014732318;
    
    uint256 constant IC9x = 8828532646084898226434501909097826225927257753178864968767358693613241740513;
    uint256 constant IC9y = 5778357150032558015556275632471065816867970044886387526906171601430184389766;
    
    uint256 constant IC10x = 20592858448828169427940708055759857178191621546158212685420159614839924400844;
    uint256 constant IC10y = 15196302844766432515372323592509844619590937611460347306655960960070346751446;
    
    uint256 constant IC11x = 21772289743035069221154812550710176858550728225809894342991959711357622856200;
    uint256 constant IC11y = 3953661099248535347783789301787948036185221095402638895362687217516946545794;
    
    uint256 constant IC12x = 16209997458799059900270720312685232550782797139441525552628970583364582581970;
    uint256 constant IC12y = 14955222167892648526294324974971299160733106392392632921037912938345806518918;
    
    uint256 constant IC13x = 13890697697766052959096731400977652728348353873944915581174702666538213384140;
    uint256 constant IC13y = 6946775439322073059907134676454793595274443598325773235783174935820676719033;
    
    uint256 constant IC14x = 8397581206637586688553828052050120424669550104577415690455961680676492118276;
    uint256 constant IC14y = 3163185119969669098431929927303286624210577159289493244003186469232122544700;
    
    uint256 constant IC15x = 10465493296435768917284196316478217943428262458600307755272635538739751042069;
    uint256 constant IC15y = 20605539122224385286630166828382892816315787447770814720840934485163701302018;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[15] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
