var prompt = require('prompt')
var colors = require('colors/safe')
var fs = require('fs')
var events = require('events');
var automation = require('./client/automation.js')

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

function generateProofInputs(fileSuffix, paymentId, cb){

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

  fs.writeFile('publicInputParameters_' + fileSuffix + '_' + paymentId, publicParameters, function(errPublic) {
    if(errPublic) {
      cb('An error occured generating the public input parameters',errPublic)
    } else {
      fs.writeFile('privateInputParameters_' + fileSuffix + '_' + paymentId, privateParameters, function(errPrivate) {
        if(errPrivate) {
          cb('An error occured generating the private input parameters',errPrivate)
        } else {
          cb('', null)
        }
      }) 
    }
  }) 
}

function checkAllFilesExist(multiOrSingle, cb){
  if(multiOrSingle=='both'){
    checkAllFilesExist('multi', function(exists){
      if(exists){
        checkAllFilesExist('single', function(exists){
          cb(exists)
        })
      } else {
        cb(false)
      }
    })
  } else {
    var fileName = 'provingKey_' + multiOrSingle
    fs.exists(fileName, (exists) => {
      cb(exists)
    })
  }
}

function checkForKeypairAndRunGenerateProof(multiOrSingle, cb){
  checkAllFilesExist(multiOrSingle, function(exists){
    if(exists==true){
      automation.LoadProvingKey(multiOrSingle)
      cb()
    } else {
      console.log("\nThe provingKey and verificationKey need to be generated\n")
      automation.GenerateNewKeyPair(multiOrSingle, function(){
        automation.LoadProvingKey(multiOrSingle)
        cb()
      })
    }
  })
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
    automation.SetProofCodeBlocking(true)
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

            generateProofInputs('multi', 1, function(msg1, err1){
              if(err1){
                console.log(msg1, err1)
              } else {
                console.log('Process started')
                automation.GenerateProof('multi', 1)
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
    automation.SetProofCodeBlocking(true)
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

      generateProofInputs('single', 1, function(msg1, err1){
        if(err1){
          console.log(msg1, err1)
        } else {
          console.log('Process started')
          automation.GenerateProof('single', 1)
        }
        cb()
      })
    })
  })
}

function handleSinglePayment(){
  if(automation.GetProofCodeBlocking()==true){
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
        automation.GenerateNewKeyPair('single', function(){
          automation.LoadProvingKey('single')
          handleSinglePayment()
        })
      } else if (answer.option == 2){
        handleGenerateSinglePaymentProof(function(){
          handleSinglePayment()
        })
      } else if(answer.option == 3){
        automation.VerifyProof('single', 1, function(verifyErr){
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
        automation.ShutDown('single')
        console.log('Quiting...')
      }
    })
  }
}

function handleMultiplePayments(){
  if(automation.GetProofCodeBlocking()==true){
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
        automation.GenerateNewKeyPair('multi', function(){
          automation.LoadProvingKey('multi')
          handleMultiplePayments()
        })
      } else if (answer.option == 2){
        handleGenerateMultiPaymentProof(function(){
          handleMultiplePayments()
        })
      } else if(answer.option == 3){
        automation.VerifyProof('multi', 1, function(verifyErr){
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
        automation.ShutDown('multi')
        console.log('Quiting...')
      }
    })
  }
}

var simulatorStatus='processing payments'
var paymentId = 10
var statusColor=colors.white
var queuedPayments = []
var unconfirmedPayments = []
var availableLiquidity = startBalance

function getUnconfirmedPaymentById(payment_id) {
  var result  = unconfirmedPayments.filter(function(o){return o.paymentId == payment_id})
  return result? result[0] : null; // or undefined
}

function removeUnconfimedPayment(payment_id){
  var arrayWithoutUnconfirmedPayment = unconfirmedPayments.filter(function( obj ) {
      return obj.paymentId != payment_id
  })
  return arrayWithoutUnconfirmedPayment
}

var onProofGenerationStarted = function (payment_id) {
  if(payment_id > 1){  //We use ids greater than 1 for the simulator
    var unconfirmedPayment = getUnconfirmedPaymentById(payment_id)
    unconfirmedPayment.status = 'Generating proof'
  }
}

var onProofGenerationComplete = function (payment_id) {
  automation.SetProofCodeBlocking(false)
  if(payment_id > 1){  //We use ids greater than 1 for the simulator
    automation.VerifyProof('single', payment_id, function(verifyErr){
      if(verifyErr){
        console.log(verifyErr)
      } else {
        //get the right payment
        var unconfirmedPayment = getUnconfirmedPaymentById(payment_id)
        unconfirmedPayment.status = 'verifying proof'
      //  console.log('payment: ', unconfirmedPayment)
        if(unconfirmedPayment.direction=='incoming'){
          startBalance = startBalance + unconfirmedPayment.amount
          availableLiquidity = availableLiquidity + unconfirmedPayment.amount
        } else {
          startBalance = startBalance - unconfirmedPayment.amount
        }
        unconfirmedPayments = removeUnconfimedPayment(payment_id)
      }
    })
  }
}

automation.Events.on('proofGenerationStarted', onProofGenerationStarted);
automation.Events.on('proofGenerationComplete', onProofGenerationComplete);

function generateSinglePaymentProofForSimulation(newPayment){
  unconfirmedPayments.push(newPayment)
  if(newPayment.direction=='incoming'){
    incoming[0] = newPayment.amount
    outgoing[0] = 0
    endBalance = startBalance + newPayment.amount
  } else {
    incoming[0] = 0
    outgoing[0] = newPayment.amount
    endBalance = startBalance - newPayment.amount
  }  
  generateProofInputs('single', paymentId, function(msg, err){
    if(err){
      console.log('Error generating proof inputs')
    } else {
      //write the proof inputs (single proof)
      automation.GenerateProof('single', paymentId)
    }
  })
}
function createANewPayment(){
  var randomNumberBetween0and2000 = Math.floor(Math.random() * 2000)
  var inOut = Math.floor(Math.random() + 0.5) == 0 ? "incoming" : "outgoing"
  paymentId++
  if(inOut=="incoming"){
    var queuedRandom = Math.floor(Math.random() + 0.5) == 0 ? "queued" : "not-queued"
    if(queuedRandom == "queued"){
      //queuedPayments.push({paymentId: paymentId, direction: inOut, amount: randomNumberBetween0and2000})
    } else {
      var newPayment = {paymentId: paymentId, direction: inOut, amount: randomNumberBetween0and2000, status: 'Payment received - unconfirmed'}
      generateSinglePaymentProofForSimulation(newPayment)
    }
  } 

  if(inOut=="outgoing" && randomNumberBetween0and2000 <= availableLiquidity){
    var newPayment = {paymentId: paymentId, direction: inOut, amount: randomNumberBetween0and2000, status: 'Payment sent - unconfirmed'}
    availableLiquidity -= newPayment.amount
    generateSinglePaymentProofForSimulation(newPayment)
  } 

  if(inOut=="outgoing" && randomNumberBetween0and2000 > startBalance){
    //queuedPayments.push({paymentId: paymentId, direction: inOut, amount: randomNumberBetween0and2000})
  } 

}

function handleSimulator(){
  if(automation.GetProofCodeBlocking()==true){
    process.stdout.write('.')
    setTimeout(handleSimulator, 500)
  } else {
    console.log('\033[2J')
    console.log('Current balance:', startBalance)
    console.log('Available liquidity:', availableLiquidity)
    console.log(statusColor('Status: ', simulatorStatus))
    console.log()
    console.log(colors.green.underline('Unconfimed payments'))
    for(var i=0; i<unconfirmedPayments.length; i++){
      if(unconfirmedPayments[i].direction=='incoming'){
        console.log(colors.green(unconfirmedPayments[i].direction + ' ' +  ('     ' + unconfirmedPayments[i].amount).slice(-5) + ' ' + unconfirmedPayments[i].status))
      } else {
        console.log(colors.red(unconfirmedPayments[i].direction + ' ' +  ('     ' + unconfirmedPayments[i].amount).slice(-5) + ' ' + unconfirmedPayments[i].status))
      }
    }
    console.log()
    console.log(colors.yellow.underline('Gridlocked payments'))
    for(var i=0; i<queuedPayments.length; i++){
      console.log(colors.yellow(queuedPayments[i].direction + ' ' + queuedPayments[i].amount))
    }

    for(var i=0; i<(20-unconfirmedPayments.length); i++){
      console.log()
    }

    createANewPayment()

    setTimeout(handleSimulator, 2500)
    
  }
}

function handleStartSelection(){
  console.log('')
  console.log('Please select an option:\n1) Single payment in and single payment out\n2) Multiple payments in and multiple payments out\n3) Simulation of an RTGS payment node\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      checkForKeypairAndRunGenerateProof('single', function(){
        handleSinglePayment()
      })
    } else if (answer.option == 2){
      checkForKeypairAndRunGenerateProof('multi', function(){
        handleMultiplePayments()
      })
    } else if (answer.option == 3){
      checkForKeypairAndRunGenerateProof('single', function(){
        handleSimulator()
      })
    } else {
      console.log('Quiting...')
    }
  })
}

handleStartSelection()
