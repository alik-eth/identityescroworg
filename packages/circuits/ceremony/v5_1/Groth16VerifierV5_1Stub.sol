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

contract Groth16VerifierV5_1Stub {
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
    uint256 constant deltax1 = 11338728390506543244637402812851684364198433369344843448709310997389554541127;
    uint256 constant deltax2 = 6490533343873826804483122065245710258362842204682328265211196223586218003661;
    uint256 constant deltay1 = 3044413740472755453592873823099437986685579702081594013564282118216231831612;
    uint256 constant deltay2 = 486239033717709790907605889217922069991312424169583581343452539721810080455;

    
    uint256 constant IC0x = 5735864718038954889841778457166013340270198966124979406085237926673720489805;
    uint256 constant IC0y = 10603073663597584191159794648807750595342914062674035649850884500951744840694;
    
    uint256 constant IC1x = 2185331619965214911843816210608283039106010332933179530941364615646315032362;
    uint256 constant IC1y = 11387216573614669685268346531776631793918509432028770915129632079420561297944;
    
    uint256 constant IC2x = 14212089425318881231504300434672022505290687729779829197878707565493265525052;
    uint256 constant IC2y = 12143936122800079679405958850347817254766266497036410688341277009788416239649;
    
    uint256 constant IC3x = 583179600789576134506208342576155337096896906460270217692419241715739337493;
    uint256 constant IC3y = 10563683876472630929709940510686311983081870309358560025610347995461028874326;
    
    uint256 constant IC4x = 18154491774032415535103437725921508230725654376999060149441992765965694756469;
    uint256 constant IC4y = 8600399311526799334222505447958969004683544608760239951416980426193215443406;
    
    uint256 constant IC5x = 8197928207062135596419943590175384174296061687905181608000397071127553028168;
    uint256 constant IC5y = 3031718216367912780557573595643608115283415848758771712260020005944463693357;
    
    uint256 constant IC6x = 14113887627452676932725293451443687367985975684580412803563112826416319988833;
    uint256 constant IC6y = 4187976122439408469346025465272140339160894473022194779902444596439206018722;
    
    uint256 constant IC7x = 9209226263938148693982430655920934303441588287768307415783498447106001807257;
    uint256 constant IC7y = 887924832790754808220009655310990780399450085090632321119083383046287836321;
    
    uint256 constant IC8x = 20912666840773410699618974515203007589826266661874317493179198285270685709110;
    uint256 constant IC8y = 10725312355881806083459645530397439776443435664429867011563740671853259732085;
    
    uint256 constant IC9x = 6529175630194098863661253548341641020439825960059440771619284464003917504467;
    uint256 constant IC9y = 19646768590676036044298872432176919251060212361919712774123785757014141162932;
    
    uint256 constant IC10x = 13321922424584255920070969731329918717183659910663355544698760017612270739112;
    uint256 constant IC10y = 9240991906389728386213880640386682530190206141887253361414747771354047466527;
    
    uint256 constant IC11x = 18746603266713823246549692786590652660940733234464671804709383840494229918118;
    uint256 constant IC11y = 3296290227458488814786531785063245677351082901090938625764753656354311900960;
    
    uint256 constant IC12x = 12303789889267727628107736273474882134325778668838924415739946400852758751528;
    uint256 constant IC12y = 8753756425373821711697251091872625807210085856737401279890230370765075986585;
    
    uint256 constant IC13x = 11584677108101056434188827960623432589022545138997926033226502045170527508126;
    uint256 constant IC13y = 343457852219832132262715160348839784206784953753814275195878270584510798535;
    
    uint256 constant IC14x = 5442922021267645621784989108266454678308173058574172423216883577871539310383;
    uint256 constant IC14y = 19787483397029025969277156942945850927595069642902987492199982448671761043367;
    
    uint256 constant IC15x = 20708959173277065858127974603929301685862459208751643336929973314509178411600;
    uint256 constant IC15y = 21372079407864363515132330308224014260020363315111721611117113872312173827870;
    
    uint256 constant IC16x = 13521714591727040528071301756870277720928113672198245796720620744767242229306;
    uint256 constant IC16y = 5084144686898892410120974256539934870689204274185202914230764521466953695292;
    
    uint256 constant IC17x = 18081916013152191889935049463076998241366194436405858848038765682127250774700;
    uint256 constant IC17y = 7399126562033442368354005416980996816310533760222167594569603017906310249736;
    
    uint256 constant IC18x = 19554842011043167891672248965937135228307255380725341509714887667121645252866;
    uint256 constant IC18y = 17609206405655626283235794091114961784150380967076741112573474257609094218512;
    
    uint256 constant IC19x = 5325464460527392221479837369284855962844019678775330444116892007396497269290;
    uint256 constant IC19y = 16658559767890507880393621897005308257598029536183090465581950081441874816679;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[19] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
