var prompt = require('prompt')
var colors = require("colors/safe")
var fs = require('fs')

const {spawn} = require('child_process')
const sha256 = require('sha256')
var runMultiProofGenerator;
var runSingleProofGenerator;

var startBalance = 0
var endBalance = 0
var incoming = [0,0,0,0,0,0]
var outgoing = [0,0,0,0,0,0]
var noPayments = 6
var proofCodeBlocking = false

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

function handleExecuteGenerateSingleProof(){

  runSingleProofGenerator.stdout.on('data', (data) => {
    dataString = data.toString()
    //console.log(dataString)

    if(dataString.indexOf('Press enter p to generate a proof or q to quit')>-1){
      console.log('\nProving key succesfully loaded\n')
      proofCodeBlocking = false
    }

    if(dataString.indexOf('System not satisfied!')>-1){
      console.log('Proof generation unsuccesful: System not satisfied')
      proofCodeBlocking = false
    }
    if(dataString.indexOf('Proving key loaded into memory')>-1){
      proofCodeBlocking = false
    }

    if(data.indexOf('Compute the proof')>-1){
      if(data.indexOf('(enter)')>-1){
        console.log('\nGenerating proof')
      } else {
        var matches = getMatches(dataString, /\[[0-9]{0,2}.[0-9]*s/g)
        var noSecs = matches[1].substring(1,matches[1].length)
        console.log('\nProof generation ended:', noSecs)
        proofCodeBlocking = false
      }
    } else {
      process.stdout.write('.')
    }

  })

  runSingleProofGenerator.stderr.on('data', (data) => {
    console.log(data.toString())
  })
}

function handleExecuteGenerateMultiProof(){

  runMultiProofGenerator.stdout.on('data', (data) => {
    dataString = data.toString()
//    console.log(dataString)

    if(dataString.indexOf('Press enter p to generate a proof or q to quit')>-1){
      console.log('\nProving key succesfully loaded\n')
      proofCodeBlocking = false
    }

    if(dataString.indexOf('System not satisfied!')>-1){
      console.log('Proof generation unsuccesful: System not satisfied')
      proofCodeBlocking = false
    }
    if(dataString.indexOf('Proving key loaded into memory')>-1){
      proofCodeBlocking = false
    }

    if(data.indexOf('Compute the proof')>-1){
      if(data.indexOf('(enter)')>-1){
        console.log('\nGenerating proof')
      } else {
        var matches = getMatches(dataString, /\[[0-9]{0,2}.[0-9]*s/g)
        var noSecs = matches[1].substring(1,matches[1].length)
        console.log('\nProof generation ended:', noSecs)
        proofCodeBlocking = false
      }
    } else {
      process.stdout.write('.')
    }

  })

  runMultiProofGenerator.stderr.on('data', (data) => {
    console.log(data.toString())
  })

}

function handleExecuteProgram(programName, msgStart, msgEnd, msgError, cb){
  console.log(msgStart)

  var succesfullyCompleted=true
  const runCommand = spawn(programName)

  runCommand.stdout.on('data', (data) => {
    dataString = data.toString()
    if(data.indexOf('(leave) Call to r1cs_ppzksnark_online_verifier_strong_IC')>-1){
      var matches = getMatches(dataString, /verifier_strong_IC.\[[0-9]{0,2}.[0-9]*s/g)
      var noSecs = ''  
      if(matches && matches.length>0){
        noSecs = matches[0].substring(20,matches[0].length)
      } else {
        console.log(dataString)
      }
      console.log('\nProof verification ended:', noSecs)
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
    proofCodeBlocking=false
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

function loadProvingKeyFromFile(multiOrSingle){
  console.log('Loading proving key from file.  This will take a few seconds')
  if(multiOrSingle=='multi'){
    runMultiProofGenerator = spawn('./payment_multi_generate_proof')
    handleExecuteGenerateMultiProof()
  } else {
    runSingleProofGenerator = spawn('./payment_in_out_generate_proof')
    handleExecuteGenerateSingleProof()
  }
}

function checkForKeypairAndRunGenerateProof(fileName, multiOrSingle, cb){
  fs.exists(fileName, (exists) => {
    if(exists==true){
      proofCodeBlocking=true
      loadProvingKeyFromFile(multiOrSingle)
    } else {
      console.log("\nThe provingKey and verificationKey need to be generated\n")
    }
    cb()
  });
}

function getPayment(incomingOrOutgoing, paymentNo, cb){
  (function getOnePrompt() {
    try {
      var schema = {
        properties: {
          payment: {
            type: 'integer',
            description: incomingOrOutgoing=='Incoming'?colors.green("Incoming payment number " + (paymentNo+1)):colors.red("Outgoing payment number " + (paymentNo+1)),
            required: true
          }
        }
      }
      prompt.get(schema, function(err, paymentAmountInputs){
        if (err) { cb(err); return }
        if(incomingOrOutgoing=='Incoming'){
          incoming[paymentNo] = parseInt(paymentAmountInputs.payment)
        } else {
          outgoing[paymentNo] = parseInt(paymentAmountInputs.payment)
        }
        paymentNo++
        if(paymentNo < noPayments){
          getOnePrompt()
        } else { 
          cb()
        }
      })
    } catch (exception) {
      cb(exception);
    }
  })();
}

function handleGenerateMultiPaymentProof(cb){
  fs.unlink('proof_multi', function(error) {
    proofCodeBlocking = true
    console.log('Please enter the amounts that are being paid')

    var paymentCount = 0;
    getPayment('Incoming', 0, function(incomingErr){
      if(incomingErr){
        console.log(incomingErr)
        cb()
      } else {
        getPayment('Outgoing', 0, function(outgoingErr){
          if(outgoingErr){
            console.log(outgoingErr)
            cb()
          } else {
            endBalance = startBalance
            for(var i=0;i<noPayments;i++){
              endBalance += incoming[i]
              endBalance -= outgoing[i]
            }

            generateProofInputs("multi", function(msg1, err1){
              if(err1){
                console.log(msg1, err1)
              } else {
                console.log('Process started')
                runMultiProofGenerator.stdin.write('p\n')
              }
              cb()
            })
          }
        })
      }
    })
  })
}

function handleGenerateSinglePaymentProof(cb){
  fs.unlink('proof_single', function(error) {
    proofCodeBlocking = true
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
        } else {
          console.log('Process started')
          runSingleProofGenerator.stdin.write('p\n')
        }
        cb()
      })
    })
  })
}

function handleSinglePayment(){
  if(proofCodeBlocking==true){
    process.stdout.write('.')
    setTimeout(handleSinglePayment, 500)
  } else {
    console.log('')
    console.log('Start balance:', startBalance)
    console.log('Incoming payment:', incoming[0])
    console.log('Outgoing payment:', outgoing[0])
    console.log('End balance:', endBalance)
    console.log('')
    console.log('Please select an option:\n1) Create a new key pair\n2) Generate a single-payment proof\n3) Verify single-payment proof\n0) Quit')
    prompt.get(['option'], function(err, answer){
      if(answer.option == 1){
        proofCodeBlocking = true
        handleExecuteProgram('./payment_in_out_generate_keypair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey and verificationKey)', 'The key pair failed\n\n', function(){
          checkForKeypairAndRunGenerateProof('provingKey_single', 'single', function(){
            handleSinglePayment()
          })
        })
      } else if (answer.option == 2){
        handleGenerateSinglePaymentProof(function(){
          handleSinglePayment()
        })
      } else if(answer.option == 3){
        handleExecuteProgram('./payment_in_out_verify_proof', '', '', 'The proof verification failed\n\n', function(verifyErr){
          if(verifyErr){
            console.log(verifyErr)
            handleSinglePayment()
          } else {
            console.log('Verification was succesful')
            startBalance = endBalance
            for(var i=0;i<noPayments;i++){
              incoming[i] = 0
              outgoing[i] = 0
            }
            handleSinglePayment()
          }
        })
      } else {
        runSingleProofGenerator.stdin.write('q\n')
        console.log('Quiting...')
      }
    })
  }
}

function handleMultiplePayments(){
  if(proofCodeBlocking==true){
    process.stdout.write('.')
    setTimeout(handleMultiplePayments, 500)
  } else {
    var totalIncoming = 0
    var totalOutgoing = 0
    for(var i=0;i<noPayments;i++){
      totalIncoming += incoming[i]
      totalOutgoing += outgoing[i]
    }

    console.log()
    console.log('Start balance:', startBalance)
    console.log('Total incoming payments:', totalIncoming)
    console.log('Total outgoing payments:', totalOutgoing)
    console.log('End balance:', endBalance)
    console.log('')
    console.log('Please select an option:\n1) Create a new key pair\n2) Generate a multi-payment proof\n3) Verify multi-payment proof\n0) Quit')
    prompt.get(['option'], function(err, answer){
      if(answer.option == 1){
        handleExecuteProgram('./payment_multi_generate_keypair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey_multi and verificationKey_multi)', 'The key pair failed\n\n', function(){
          checkForKeypairAndRunGenerateProof('provingKey_multi', 'multi', function(){
            handleMultiplePayments()
          })
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
        runMultiProofGenerator.stdin.write('q\n')
        console.log('Quiting...')
      }
    })
  }
}

function handleStartSelection(){
  console.log('')
  console.log('Please select an option:\n1) Single payment in and single payment out\n2) Multiple payments in and multiple payments out\n3) Simulation of an RTGS payment node\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      checkForKeypairAndRunGenerateProof('provingKey_single', 'single', function(){
        handleSinglePayment()
      })
    } else if (answer.option == 2){
      checkForKeypairAndRunGenerateProof('provingKey_multi', 'multi', function(){
        handleMultiplePayments()
      })
    } else {
      console.log('Quiting...')
    }
  })
}

handleStartSelection()
