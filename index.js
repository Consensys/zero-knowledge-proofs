var prompt = require('prompt');
var fs = require('fs');

const {spawn} = require('child_process');
const sha256 = require('sha256')

var startBalance = 0
var endBalance = 0
var incoming = [0,0,0,0,0,0]
var outgoing = [0,0,0,0,0,0]
var noPayments = 6

if(process.argv.length!=3){
  console.log("you need to set your start balance.  Run the application using node index.js startBalance=1000")
  return 1
}

process.argv.forEach(function (val, index, array) {
  if(val.startsWith("startBalance")){
    startBalance = parseInt(val.split("=")[1])
    endBalance = startBalance
  }
});

function getMatches(string, regex) {
  var matches = [];
  var match;
  while (match = regex.exec(string)) {
    matches.push(match[0]);
  }
  return matches;
}

function handleExecuteProgram(programName, msgStart, msgEnd, msgError, cb){
  console.log(msgStart)

  var succesfullyCompleted=true
  const runCommand = spawn(programName)

  runCommand.stdout.on('data', (data) => {
    dataString = data.toString()
    if(dataString.indexOf('System not satisfied!')>-1){
      succesfullyCompleted = false
    }
    if(data.indexOf('Compute the proof')>-1){
      if(data.indexOf('(enter)')>-1){
        console.log('\nProof generation started')
      } else {
        var matches = getMatches(dataString, /[0-9].[0-9]*s/g)
        var noSecs = matches[2]
        console.log('\nProof generation ended:', noSecs)
      }
    } else {
      process.stdout.write('.')
    }
  })

  runCommand.stderr.on('data', (data) => {
    console.log(data.toString())
    succesfullyCompleted = false
  })

  runCommand.on('close', (code) => {
    console.log()
    if(code=='1' || !succesfullyCompleted){
      cb(msgError)
    } else {
      cb(null)
    }
  })
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

function getArray(value){
  var r_value = longToByteArray(value)
  var arr_salt = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
  return r_value.concat(arr_salt)
}

function getListOfArrays(inputArray){
  returnVal = []
  for(var i=0;i<noPayments;i++){
    returnVal.push(getArray(inputArray[i]))
  }
  return returnVal
}

function getListOfBuffers(inputArray){
  returnVal = []
  for(var i=0;i<noPayments;i++){
    returnVal.push(Buffer.from(inputArray[i]))
  }
  return returnVal
}

function getListOfSha(inputArray){
  returnVal = []
  for(var i=0;i<noPayments;i++){
    returnVal.push(sha256(inputArray[i], {asBytes: true}))
  }
  return returnVal
}

function generateProofInputs(fileSuffix, cb){

  var arr_startBalance = getArray(startBalance)
  var arr_endBalance = getArray(endBalance)
  var arr_incoming = getListOfArrays(incoming)
  var arr_outgoing = getListOfArrays(outgoing)

  var b_startBalance = Buffer.from(arr_startBalance)
  var b_endBalance = Buffer.from(arr_endBalance)
  var b_incoming = getListOfBuffers(arr_incoming)
  var b_outgoing = getListOfBuffers(arr_outgoing)

  var public_startBalance = sha256(b_startBalance, {asBytes: true})
  var public_endBalance = sha256(b_endBalance, {asBytes: true})
  var public_incoming = getListOfSha(b_incoming)
  var public_outgoing = getListOfSha(b_outgoing)

  var publicParameters = public_startBalance.toString().replace(/,/g, ' ') + "\n"
  publicParameters += public_endBalance.toString().replace(/,/g, ' ') + "\n"
  publicParameters += public_incoming[0].toString().replace(/,/g, ' ') + "\n"

  if(fileSuffix=="multi"){
    for(var i=1;i<noPayments;i++){
      publicParameters += public_incoming[i].toString().replace(/,/g, ' ') + "\n"
    }
  }

  publicParameters += public_outgoing[0].toString().replace(/,/g, ' ') + "\n"
  if(fileSuffix=="multi"){
    for(var i=1;i<noPayments;i++){
      publicParameters += public_outgoing[i].toString().replace(/,/g, ' ') + "\n"
    }
  }

  var privateParameters = arr_startBalance.toString().replace(/,/g, ' ') + "\n"
  privateParameters += arr_endBalance.toString().replace(/,/g, ' ') + "\n"
  privateParameters += arr_incoming[0].toString().replace(/,/g, ' ') + "\n"
  if(fileSuffix=="multi"){
    for(var i=1;i<noPayments;i++){
      privateParameters += arr_incoming[i].toString().replace(/,/g, ' ') + "\n"
    }
  }
  privateParameters += arr_outgoing[0].toString().replace(/,/g, ' ') + "\n"
  if(fileSuffix=="multi"){
    for(var i=1;i<noPayments;i++){
      privateParameters += arr_outgoing[i].toString().replace(/,/g, ' ') + "\n"
    }
  }

  fs.writeFile('publicInputParameters_' + fileSuffix, publicParameters, function(errPublic) {
    if(errPublic) {
      cb('An error occured generating the public input parameters',errPublic)
    } else {
      fs.writeFile('privateInputParameters_' + fileSuffix, privateParameters, function(errPrivate) {
        if(errPrivate) {
          cb('An error occured generating the private input parameters',errPrivate)
        } else {
          cb('', null)
        }
      }) 
    }
  }) 
}

function handleGenerateMultiPaymentProof(cb){
  fs.unlink('proof1', function(error) {
    console.log('Please enter the amounts that are being paid')
    prompt.get(['incoming1', 'incoming2', 'incoming3','incoming4', 'incoming5', 'incoming6', 'outgoing1', 'outgoing2', 'outgoing3', 'outgoing4', 'outgoing5', 'outgoing6'], function(err, paymentAmountInputs){
      incoming[0] = parseInt(paymentAmountInputs.incoming1)
      incoming[1] = parseInt(paymentAmountInputs.incoming2)
      incoming[2] = parseInt(paymentAmountInputs.incoming3)
      incoming[3] = parseInt(paymentAmountInputs.incoming4)
      incoming[4] = parseInt(paymentAmountInputs.incoming5)
      incoming[5] = parseInt(paymentAmountInputs.incoming6)
      outgoing[0] = parseInt(paymentAmountInputs.outgoing1)
      outgoing[1] = parseInt(paymentAmountInputs.outgoing2)
      outgoing[2] = parseInt(paymentAmountInputs.outgoing3)
      outgoing[3] = parseInt(paymentAmountInputs.outgoing4)
      outgoing[4] = parseInt(paymentAmountInputs.outgoing5)
      outgoing[5] = parseInt(paymentAmountInputs.outgoing6)
      endBalance = startBalance
      for(var i=0;i<noPayments;i++){
        endBalance += incoming[i]
        endBalance -= outgoing[i]
      }

      generateProofInputs("multi", function(msg1, err1){
        if(err1){
          console.log(msg1, err1)
          cb()
        } else {
          handleExecuteProgram('./payment_multi_generate_proof', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(msgGenerateProof){
            if(msgGenerateProof){
              console.log('\n' + msgGenerateProof)
            }
            cb()
          })
        }
      })
    })
  })
}

function handleGenerateSinglePaymentProof(cb){
  fs.unlink('proof1', function(error) {
    console.log('Please enter the amounts that are being paid')
    prompt.get(['incoming', 'outgoing'], function(err, paymentAmountInputs){
      incoming[0] = parseInt(paymentAmountInputs.incoming)
      incoming[1] = 0
      incoming[2] = 0
      incoming[3] = 0
      outgoing[0] = parseInt(paymentAmountInputs.outgoing)
      outgoing[1] = 0
      outgoing[2] = 0
      outgoing[3] = 0
      endBalance = startBalance + incoming[0] - outgoing[0]

      generateProofInputs("single", function(msg1, err1){
        if(err1){
          console.log(msg1, err1)
          cb()
        } else {
          handleExecuteProgram('./payment_in_out_generate_proof', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(msgGenerateProof){
            if(msgGenerateProof){
              console.log('\n' + msgGenerateProof)
            }
            cb()
          })
        }
      })
    })
  })
}

function handleSinglePayments(){
  console.log('Start balance:', startBalance)
  console.log('Incoming payment:', incoming[0])
  console.log('Outgoing payment:', outgoing[0])
  console.log('End balance:', endBalance)
  console.log('')
  console.log('Please select an option:\n1) Create a new key pair\n2) Generate a single-payment proof\n3) Verify single-payment proof\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleExecuteProgram('./payment_in_out_generate_keypair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey and verificationKey)', 'The key pair failed\n\n', function(){
        handleSinglePayments()
      })
    } else if (answer.option == 2){
      handleGenerateSinglePaymentProof(function(){
        handleSinglePayments()
      })
    } else if(answer.option == 3){
      handleExecuteProgram('./payment_in_out_verify_proof', '', '', 'The proof verification failed\n\n', function(verifyErr){
        if(verifyErr){
          console.log(verifyErr)
          handleSinglePayments()
        } else {
          console.log('Verification was succesful')
          startBalance = endBalance
          for(var i=0;i<noPayments;i++){
            incoming[i] = 0
            outgoing[i] = 0
          }

          handleSinglePayments()
        }
      })
    } else {
      console.log('Quiting...')
    }
  })
}

function handleMultiplePayments(){
  console.log('Start balance:', startBalance)
  var totalIncoming = 0
  var totalOutgoing = 0
  for(var i=0;i<noPayments;i++){
    totalIncoming += incoming[i]
    totalOutgoing += outgoing[i]
  }
  
  console.log('Total incoming payments:', totalIncoming)
  console.log('Total outgoing payments:', totalOutgoing)
  console.log('End balance:', endBalance)
  console.log('')
  console.log('Please select an option:\n1) Create a new key pair\n2) Generate a multi-payment proof\n3) Verify multi-payment proof\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleExecuteProgram('./payment_multi_generate_keypair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey_multi and verificationKey_multi)', 'The key pair failed\n\n', function(){
        handleMultiplePayments()
      })
    } else if (answer.option == 2){
      handleGenerateMultiPaymentProof(function(){
        handleMultiplePayments()
      })
    } else if(answer.option == 3){
      handleExecuteProgram('./payment_multi_verify_proof', '', '', 'The proof verification failed\n\n', function(verifyErr){
        if(verifyErr){
          console.log(verifyErr)
          handleMultiplePayments()
        } else {
          console.log('Verification was succesful')
          startBalance = endBalance
          for(var i=0;i<noPayments;i++){
            incoming[i] = 0
            outgoing[i] = 0
          }
          
          handleMultiplePayments()
        }
      })
    } else {
      console.log('Quiting...')
    }
  })
}

function handleStartSelection(){
  console.log('')
  console.log('Please select an option:\n1) Single payment in and single payment out\n2) Multiple payments in and multiple payments out\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleSinglePayments()
    } else if (answer.option == 2){
      handleMultiplePayments()
    } else {
      console.log('Quiting...')
    }
  })
}

handleStartSelection()
