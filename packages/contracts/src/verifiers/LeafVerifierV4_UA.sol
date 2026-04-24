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

contract Groth16Verifier {
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
    uint256 constant deltax1 = 5307620562363266554404114677059596995091252322735154725716199030245827820356;
    uint256 constant deltax2 = 10370792435753150332721134210365182680502931129660375842983535287023966677587;
    uint256 constant deltay1 = 6654354889732458602904997606054325010599627449229351693330739060838691668568;
    uint256 constant deltay2 = 18099672848240366925481829742371412860855348706083728315079451795134846484605;

    
    uint256 constant IC0x = 17234164358999062856324792951991274458958642445028561674694348177664929948404;
    uint256 constant IC0y = 5666907305601805055010258143478696203330483237752353582239991069785441486408;
    
    uint256 constant IC1x = 8811271634474217381210876845429502546284669144890511163835113740764003021534;
    uint256 constant IC1y = 17144890429278995208966925764080834795312090810523350793014064580107649168637;
    
    uint256 constant IC2x = 19961607819466770730995243217293044987760912527028556255144174464706475001041;
    uint256 constant IC2y = 16624270929729967926050606285454243450220787706620018065224600854383328763344;
    
    uint256 constant IC3x = 11486030513263692523128967162726169438095380109699644744831465254950335425685;
    uint256 constant IC3y = 13742529119879990527654405979625252915320899136967342782224300919672487945912;
    
    uint256 constant IC4x = 1032966822230923060257201042452908662916573576026403063558340227058732826661;
    uint256 constant IC4y = 6650882509126028644883282428839582268758111306286385763865868879612742628671;
    
    uint256 constant IC5x = 453335750916422064339161608770520557894814314967138501216555905664924838231;
    uint256 constant IC5y = 4028652616147997007643451748716458246703988652084216262117135941014423220581;
    
    uint256 constant IC6x = 18057052451007076871019877105665490516104303775932456049346602135787164693401;
    uint256 constant IC6y = 8607439929268479367140250245931096827125492491129354559103600272845452006700;
    
    uint256 constant IC7x = 4175472948084382770014306668490675426864257696423711653046616439450161260649;
    uint256 constant IC7y = 1259188451603177803681480778464898732579841560333312847010387489142423964919;
    
    uint256 constant IC8x = 18601028751753295887300447913838401556840437631092775349705917329441823712889;
    uint256 constant IC8y = 18909449170488012257524571362203510753822585678106264477497356559025243666848;
    
    uint256 constant IC9x = 6941386302135021246774625798078879761178009478432418049359699528272822777678;
    uint256 constant IC9y = 20480019705964710246661476570049443291996482780860167641563548500301685423515;
    
    uint256 constant IC10x = 7237462765354694642493501893459489367168942173641886783637475651710115148581;
    uint256 constant IC10y = 8222899713133522563774952941608199119069220408740756068952639875389050167101;
    
    uint256 constant IC11x = 17078484423118070443336447642244783883706306130212873839104366558183549164662;
    uint256 constant IC11y = 2695885507420809556722139543439028324178987172179477796173528713160716438450;
    
    uint256 constant IC12x = 9810668172246292052468648427227804166220956870424382379845158149988647417228;
    uint256 constant IC12y = 11245918516056251927203312866682161068135811754413145307762999189775231697771;
    
    uint256 constant IC13x = 685489046399455225997466721248180978737847625536282850006787064566168477047;
    uint256 constant IC13y = 3755564685026125963897035607101092890772446985268647237772188427643958220918;
    
    uint256 constant IC14x = 16882882495747086172132510919899239851685633102891731431419959039247294462069;
    uint256 constant IC14y = 20430022698074108300220872217043725347678985155344966311131189233418166289442;
    
    uint256 constant IC15x = 19035829074856385288718115338088177159570483559771755018310560522401659163444;
    uint256 constant IC15y = 15584303196623992923739496373089478901112021094742239667450682444886467984598;
    
    uint256 constant IC16x = 18422600753276038854638321059259967156098265526694295307576862865856075569838;
    uint256 constant IC16y = 5567322956997114864526280935236337852418496721929801076057587241355552363571;
    
 
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
