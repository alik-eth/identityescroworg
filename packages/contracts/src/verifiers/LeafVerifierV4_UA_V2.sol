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

contract LeafVerifierV4_UA_V2 {
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
    uint256 constant deltax1 = 18400075206942931015358812343336606844438934956104002029756633126587234832338;
    uint256 constant deltax2 = 8745125907893579092512297945081377377324467517570968935387057185797970350919;
    uint256 constant deltay1 = 14921508126532326794777147698934217878495749620444944736202029753439463089688;
    uint256 constant deltay2 = 9606953687476175324060767142255759283361592359759396182220978847535691952944;

    
    uint256 constant IC0x = 20825007312647489410189471349026485322959691467169835866275034940683632501630;
    uint256 constant IC0y = 673884922530124749315787162199657994278505542080062395585247221251215051004;
    
    uint256 constant IC1x = 16905753480530634554167206914824308010849992567723970450828440737701315069077;
    uint256 constant IC1y = 754723718416694099381295070338659333419560994835102381221060876629912272797;
    
    uint256 constant IC2x = 9260436753767367073931925292969921501638996404699660298875344615947450899949;
    uint256 constant IC2y = 3886252242194909725152257827554098002154178634760266932715379580353949442302;
    
    uint256 constant IC3x = 14401130386465611144785088769851000744080650818019777709865048507504879433920;
    uint256 constant IC3y = 1202631637448474603102654812062410590803523766341363980352289791497786220488;
    
    uint256 constant IC4x = 14339475447716752504328452433288712718992864340545081556085563832340049589258;
    uint256 constant IC4y = 5384909044792850654571154956042493144531507044188711102291333272388862370039;
    
    uint256 constant IC5x = 19964786191697578660879075084456726988447616902101197009600722099877855364001;
    uint256 constant IC5y = 12559098910145354379788088557149030597652329240537793523899581410012290974731;
    
    uint256 constant IC6x = 21396944070974313424403803486682701479478975465166882146563676894297039492082;
    uint256 constant IC6y = 8728560888488979310307888641409214961991284306398616519206658196726469097567;
    
    uint256 constant IC7x = 21149895631057406995454756869924331594385215520655949709953348511173002058362;
    uint256 constant IC7y = 13697483968301369872850089249306599266604478131321412870761912624347942916948;
    
    uint256 constant IC8x = 18673354090598234949362224218036215578949469323677635120529366685075400106204;
    uint256 constant IC8y = 12675698790000276045146987088667142928127439030922188855414328455108430284858;
    
    uint256 constant IC9x = 9617801086190961559790724355730203619742336777539463699063535681918996155518;
    uint256 constant IC9y = 3087756461388448746299483962295642569124822559856551345560794584500490572959;
    
    uint256 constant IC10x = 10525288188453776025439899498172468904566985864858023720542677557552803197849;
    uint256 constant IC10y = 3568329786323812777436271841242247009924124921536488221905285737129714915397;
    
    uint256 constant IC11x = 4760990869906575623197808514540397003439495094919663791371104317845995573915;
    uint256 constant IC11y = 10645077812345689020102040517982569655140305360336167559171994757427889967883;
    
    uint256 constant IC12x = 15381265746281513354118035159504608232754207808894549175464948180352896108664;
    uint256 constant IC12y = 9361444669027742779112851848872239240078662585325321341127680541679429700529;
    
    uint256 constant IC13x = 11799415087117706136017111178600769873209800659728046957427272220032489160035;
    uint256 constant IC13y = 1151014478317442227802619978232351939343824741404671255944105431032310525928;
    
    uint256 constant IC14x = 13025102110279321241794189741374085479013629538527321252521609613578291780687;
    uint256 constant IC14y = 1185095394176616110324332634427544575873709520913626733240613443557667731627;
    
    uint256 constant IC15x = 3400588159608415461052245532718309935055144696876414931858797742693164075516;
    uint256 constant IC15y = 12271834005006497630678678915572703046701240520811150274836208702190286592415;
    
    uint256 constant IC16x = 13106285212279916099605512778883809547226959900045460098433737611429261521033;
    uint256 constant IC16y = 19882016645941246497404766549416313232835115915218508815863273513410972474456;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[16] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                

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
            
            checkField(calldataload(add(_pubSignals, 480)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
