var prompt = require('prompt');
var fs = require('fs');

const {exec} = require( 'child_process' )
const sha256 = require('sha256')

var startBalance = 0
var endBalance = 0
var intermediateBalance = 0
var incoming1 = 0
var incoming2 = 0
var outgoing1 = 0
var outgoing2 = 0

if(process.argv.length!=3){
  console.log("you need to set your start balance.  Run the application using node index.js startBalance=1000")
  return 1
}

process.argv.forEach(function (val, index, array) {
  if(val.startsWith("startBalance")){
    startBalance = parseInt(val.split("=")[1])
    intermediateBalance = startBalance
    endBalance = startBalance
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

function handleGenerateMultiPaymentProof(cb){
  fs.unlink('proof1', function(error) {
  fs.unlink('proof2', function(error) {
  fs.unlink('proof3', function(error) {
  fs.unlink('proof4', function(error) {
    console.log('Please enter the amounts that are being paid')
    prompt.get(['incoming1', 'incoming2', 'outgoing1', 'outgoing2'], function(err, paymentAmountInputs){
      incoming1 = parseInt(paymentAmountInputs.incoming1)
      incoming2 = parseInt(paymentAmountInputs.incoming2)
      outgoing1 = parseInt(paymentAmountInputs.outgoing1)
      outgoing2 = parseInt(paymentAmountInputs.outgoing2)
      intermediateBalance = startBalance + incoming1 + incoming2
      endBalance = intermediateBalance - outgoing1 - outgoing2

      generateProofInputs(startBalance, (incoming1 + incoming2), intermediateBalance, 'proof1Inputs', function(msg1, err1){
        if(err1){
          console.log(msg1, err1)
          cb()
        } else {
          console.log(msg1)

          generateProofInputs(endBalance, (outgoing1 + outgoing2), intermediateBalance, 'proof2Inputs', function(msg2, err2){
            if(err2){
              console.log(msg2, err2)
              cb()
            } else {
              console.log(msg2)

              generateProofInputs(incoming1, incoming2, (incoming1 + incoming2), 'proof3Inputs', function(msg3, err3){
                if(err3){
                  console.log(msg3, err3)
                  cb()
                } else {
                  console.log(msg3)

                  generateProofInputs(outgoing1, outgoing2, (outgoing1 + outgoing2), 'proof4Inputs', function(msg4, err4){
                    if(err4){
                      console.log(msg4, err4)
                      cb()
                    } else {
                      console.log(msg4)
                      handleExecuteProgram('./generateProof', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(){
                        cb()
                      })
                    }
                  })
                }
              })
            }
          })
        }
      })
    })
  })
  })
  })
  })
}

function handleInput(){
  console.log('Start balance:', startBalance)
  console.log('Total incoming payments:', (incoming1 + incoming2))
  console.log('Total outgoing payments:', (outgoing1 + outgoing2))
  console.log('End balance:', endBalance)
  console.log('')
  console.log('Please select an option:\n1) Create a new key pair\n2) Generate a multi-payment proof\n3) Verify multi-payment proof\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleExecuteProgram('./generateKeyPair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey and verificationKey)', 'The key pair failed\n\n', function(){
        handleInput()
      })
    } else if (answer.option == 2){
      handleGenerateMultiPaymentProof(function(){
        handleInput()
      })
    } else if(answer.option == 3){
      handleExecuteProgram('./verifyProof', '', '', 'The proof verification failed\n\n', function(verifyErr){
        if(verifyErr){
          console.log(verifyErr)
          handleInput()
        } else {
          console.log('Verification was succesful')
          startBalance = endBalance
          intermediateBalance = endBalance
          incoming1 = 0
          incoming2 = 0
          outgoing1 = 0
          outgoing2 = 0
          
          handleInput()
        }
      })
    } else {
      console.log('Quiting...')
    }
  })
}

handleInput()
