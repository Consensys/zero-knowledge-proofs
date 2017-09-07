var prompt = require('prompt');
var fs = require('fs');

const {exec} = require( 'child_process' )
const sha256 = require('sha256')

var senderBalance = 0
var paymentAmount = 0
var receiverBalance = 0

if(process.argv.length!=4){
  console.log("you need to setup the sender and receiver balance.  Run the application using node index.js senderBalance=100 receiverBalance=50")
  return 1
}

process.argv.forEach(function (val, index, array) {
  if(val.startsWith("senderBalance")){
    senderBalance = parseInt(val.split("=")[1]);
  }
  if(val.startsWith("receiverBalance")){
    receiverBalance = parseInt(val.split("=")[1]);
  }
});

function handleExecuteProgram(programName, msgStart, msgEnd, msgError, cb){
  console.log(msgStart)
  exec(programName, (error, stdout, stderr) => {
    console.log(`stdout: ${stdout}`)
    if (error) {
      console.error(`exec error: ${error}`)
      console.log(msgError)
      cb(error)
    } else if(stderr){
      console.log(`stderr: ${stderr}`)
      console.log(msgError)
      cb(msgError)
    } else {
      console.log(msgEnd)
      cb(null)
    }
  });
}

longToByteArray = function(valueToConvert) {
  // we want to represent the input as a 8-bytes array
  var byteArray = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

  for ( var index = byteArray.length-1; index >=0; index -- ) {
      var byte = valueToConvert & 0xff
      byteArray [ index ] = byte
      valueToConvert = (valueToConvert - byte) / 256 
  }

  return byteArray;
}

function generateProofInputs(r1, r2, r3, fileName, cb){

  //proof is that r1+r2=r3
  var arr_r1_value = longToByteArray(r1);
  var arr_r2_value = longToByteArray(r2);
  var arr_r3_value = longToByteArray(r3);

  var arr_r1_salt = [202, 5, 190, 15, 140, 211, 75, 131, 62, 136, 12, 6, 17, 4, 10, 18];
  var arr_r2_salt = [6, 171, 218, 43, 241, 15, 217, 251, 205, 248, 0, 21, 86, 194, 100, 94];
  var arr_r3_salt = [200, 1, 111, 160, 141, 10, 73, 36, 65, 16, 15, 6, 17, 2, 11, 8];

  var arr_r1 = arr_r1_value.concat(arr_r1_salt);
  var arr_r2 = arr_r2_value.concat(arr_r2_salt);
  var arr_r3 = arr_r3_value.concat(arr_r3_salt);

  var r1_b = Buffer.from(arr_r1)
  var r2_b = Buffer.from(arr_r2)
  var r3_b = Buffer.from(arr_r3)

  var r1_i = parseInt(r1_b.toString('hex'), 16)
  var r2_i = parseInt(r2_b.toString('hex'), 16)
  var r3_i = parseInt(r3_b.toString('hex'), 16)

  var h1_b = sha256(r1_b, {asBytes: true})
  var h2_b = sha256(r2_b, {asBytes: true})
  var h3_b = sha256(r3_b, {asBytes: true})

  var inputParameters = h1_b.toString().replace(/,/g, ' ') + "\n";
  inputParameters += h2_b.toString().replace(/,/g, ' ') + "\n";
  inputParameters += h3_b.toString().replace(/,/g, ' ') + "\n";
  inputParameters += arr_r1.toString().replace(/,/g, ' ') + "\n";
  inputParameters += arr_r2.toString().replace(/,/g, ' ') + "\n";
  inputParameters += arr_r3.toString().replace(/,/g, ' ');
  fs.writeFile(fileName, inputParameters, function(err) {
    if(err) {
      cb('An error occured generating the input parameters:',err);
    } else {
      cb('The input parameters were succesfully generated and saved to the file: ' + fileName, null);
    }
  }); 
}

function handleUpdateOpeningBalancesAndPaymentAmount(cb){
  console.log('Please enter the senders starting balance')
  prompt.get(['option'], function(err, sendersBalance){
    console.log('Please enter the receivers starting balance')
    prompt.get(['option'], function(err, receiversBalance){
      console.log('Please enter the amount that is being paid')
      prompt.get(['option'], function(err, paymentAmount){
        sBal = parseInt(sendersBalance.option)
        rBal = parseInt(receiversBalance.option)
        pAmount = parseInt(paymentAmount.option)
        cb()
      })
    })
  })
}

function handleGenerateSendPaymentProof(cb){
  fs.unlink('sendProof', function(error) {
    fs.unlink('receiveProof', function(error) {
      console.log('Please enter the amount that is being paid')
      prompt.get(['option'], function(err, paymentAmountInput){
        paymentAmount = parseInt(paymentAmountInput.option)
        generateProofInputs((senderBalance - paymentAmount), paymentAmount, senderBalance, 'sendProofInputs', function(msg, err){
          if(err){
            console.log(msg, err)
            cb()
          } else {
            console.log(msg)
            handleExecuteProgram('./generateProof sendProof sendProofInputs', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(){
              cb()
            })
          }
        })
      })
    })
  })
}

function handleGenerateReceivePaymentProof(cb){
  generateProofInputs(receiverBalance, paymentAmount, (receiverBalance + paymentAmount), 'receiveProofInputs', function(msg, err){
    if(err){
      console.log(msg, err)
      cb()
    } else {
      console.log(msg)
      handleExecuteProgram('./generateProof receiveProof receiveProofInputs', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(){
        cb()
      })
    }
  })
}

function handleInput(){
  console.log('Sender balance:', senderBalance)
  console.log('Receiver balance:', receiverBalance)
  console.log('Please select an option:\n1) Create a new key pair\n2) Generate a send payment proof\n3) Generate a receive payment proof\n4) Verify proofs\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleExecuteProgram('./generateKeyPair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey and verificationKey)', 'The key pair failed\n\n', function(){
        handleInput()
      })
    } else if (answer.option == 2){
      handleGenerateSendPaymentProof(function(){
        handleInput()
      })
    } else if (answer.option == 3){
      handleGenerateReceivePaymentProof(function(){
        handleInput()
      })
    } else if(answer.option == 4){
      handleExecuteProgram('./verifyProof sendProof sendProofInputs', '', '', 'The proof verification failed\n\n', function(sendProofErr){
        if(sendProofErr){
          console.log(sendProofErr)
          handleInput()
        } else {
          console.log('Send proof verification was succesful')
          handleExecuteProgram('./verifyProof receiveProof receiveProofInputs', '', '', 'The proof verification failed\n\n', function(receiveProofErr){
            if(receiveProofErr){
              console.log(receiveProofErr)
            } else {
              console.log('Receive proof verification was succesful')
              senderBalance = senderBalance - paymentAmount
              receiverBalance = receiverBalance - paymentAmount
              paymentAmount = 0 //This stops the balances being changed if proof verification is run multiple times
            }
            handleInput()
          })
        }
      })
    } else {
      console.log('Quiting...')
    }
  })
}

handleInput()
