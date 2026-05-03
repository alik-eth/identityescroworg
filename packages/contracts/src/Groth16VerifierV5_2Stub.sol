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

contract Groth16VerifierV5_2Stub {
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
    uint256 constant deltax1 = 13592616035355438504008030091842700705784648917789476896903742319974474632201;
    uint256 constant deltax2 = 8000140686709119920976227983214973877329191236649866408021879473520580446378;
    uint256 constant deltay1 = 21854193314376763070747337124151679722984778645595527122385888263788546143979;
    uint256 constant deltay2 = 13210483524568618982792451890141013889588819937662060070833854284390419370302;

    
    uint256 constant IC0x = 1981595946245915398953333922192886258408646310787069908464185984012772784039;
    uint256 constant IC0y = 402203910603256229687347908858656873176420259081197167768290618903247058384;
    
    uint256 constant IC1x = 5015497717707331890546583041366388079071851139893865013799394855596529691934;
    uint256 constant IC1y = 6725697741439391226256513322068340058339131245972175371883127788250249355108;
    
    uint256 constant IC2x = 18078862299973148190196876450846181568209193828532958542632044928802556118249;
    uint256 constant IC2y = 7721837106527897772212288488639184507785182830712678606575926626759153155916;
    
    uint256 constant IC3x = 17581393533531659509976058447736095975340149448041739569782251145998276450029;
    uint256 constant IC3y = 11812715197829051366987931710672355899142560492607912776552043365720916268323;
    
    uint256 constant IC4x = 13957612518826096969922412003890005986395363136327342416771657306361453595845;
    uint256 constant IC4y = 12421134897849631975172526432363326075986767120872270470850131616362253825604;
    
    uint256 constant IC5x = 4578712784870977905250040713068757336825143252795081555861643761788740448002;
    uint256 constant IC5y = 21758147015702668430106475866632305058349038105080060887550440475906947957124;
    
    uint256 constant IC6x = 15846692415508376549675790054807023176065485449460496867895686209798098062847;
    uint256 constant IC6y = 9064876311981332995841395312576837211704273191315529298351115768052032257322;
    
    uint256 constant IC7x = 15261557557524736195506133131456541671102551000364477228339954093112683357563;
    uint256 constant IC7y = 1150358254951066549432478603161327620484395371402526115739016292389843235015;
    
    uint256 constant IC8x = 22934431900509248813129365409729948590540526248757679493857528670693276731;
    uint256 constant IC8y = 18537222476928318991580294847598537801589483642901560196482521586763466860402;
    
    uint256 constant IC9x = 11998888508445155889237458427051593265526948699013974694243030449868671751168;
    uint256 constant IC9y = 744760054443758532840698146013900703822146107718009291929365854473057035790;
    
    uint256 constant IC10x = 18455221805238595911299033786123685327292571709416152150221943250782167871378;
    uint256 constant IC10y = 106005742115859873415217190513489807734341605648836401725571644849371797637;
    
    uint256 constant IC11x = 21321697224406343203036478688573158183317823753070975996392844518542985779332;
    uint256 constant IC11y = 4860760211704878046208919073702726086291583444676588445589031172264152238164;
    
    uint256 constant IC12x = 18242514386702443274813797311430784171142250058559000046853621201382216618913;
    uint256 constant IC12y = 8193471639492739908629977773357082090057898540722576953843398854734508262832;
    
    uint256 constant IC13x = 18472915030932603875983032922234693062234375582833000098233922581173747731520;
    uint256 constant IC13y = 6627475423175606539078939873663829975565897740654645297489908977800418707331;
    
    uint256 constant IC14x = 1913850084053088573752263347978532021058737930419141087901756367343554573731;
    uint256 constant IC14y = 197332987639394622554606121578803530985433844934795868964595450386066621780;
    
    uint256 constant IC15x = 2801906469689915677130210380660730467747364449578736014999640316685158664878;
    uint256 constant IC15y = 11131715760075014346226829249818392824286897071337181712222902483514001590334;
    
    uint256 constant IC16x = 14876547644555472030458411096421350540073064895943991856563877017832943334009;
    uint256 constant IC16y = 570569107224711732534525927647164115821530858861942490042513190767626552268;
    
    uint256 constant IC17x = 21655699131149696510047783612519767410760311665659744956123738381886460723710;
    uint256 constant IC17y = 12641586860406875776363004009317916552395671954571002187420603197280975753847;
    
    uint256 constant IC18x = 9112029326674081958886704916323412300710556578432009888009861143662236393919;
    uint256 constant IC18y = 6330426719490077973079647658373803927172450072581359462499041816632648890094;
    
    uint256 constant IC19x = 1354893478531457592151938979510470185334858367021224785902197564902356248282;
    uint256 constant IC19y = 11118945972041142117425189840739216711292966584060719536068333867396962628979;
    
    uint256 constant IC20x = 21689486145884137378265442266580003847410874004166700786933556567592727605411;
    uint256 constant IC20y = 8945219651703683000815511410382677867829794960478491665124390214985796400182;
    
    uint256 constant IC21x = 18363634332762184850941432021841706316916482195971957683355418642237758843919;
    uint256 constant IC21y = 17788587905240743305675030292638605414377428348376178331758637290767422018714;
    
    uint256 constant IC22x = 16956548432738249246247451324465916222275995575325602880076412956181348951402;
    uint256 constant IC22y = 4745786506640363946949779921385839079648784293555630985453582355361874471030;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[22] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                

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
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
