var prompt = require('prompt');
var fs = require('fs');

const {exec} = require( 'child_process' )
const {spawn} = require('child_process');
const sha256 = require('sha256')

var startBalance = 0
var endBalance = 0
var intermediateBalance = 0
var incoming = 0
var outgoing = 0

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
    cb(data.toString())
  })

  runCommand.on('close', (code) => {
    console.log()
    if(code=='1' || !succesfullyCompleted){
      cb(msgError)
    } else {
      cb(null)
    }
  })

/*
  spawn(programName, (error, stdout, stderr) => {
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
*/
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
      cb('', null);
    }
  }); 
}

function handleGenerateMultiPaymentProof(cb){
  fs.unlink('proof1', function(error) {
  fs.unlink('proof2', function(error) {
    console.log('Please enter the amounts that are being paid')
    prompt.get(['incoming', 'outgoing'], function(err, paymentAmountInputs){
      incoming = parseInt(paymentAmountInputs.incoming)
      outgoing = parseInt(paymentAmountInputs.outgoing)
      intermediateBalance = startBalance + incoming
      endBalance = intermediateBalance - outgoing

      generateProofInputs(startBalance, incoming, intermediateBalance, 'proof1Inputs', function(msg1, err1){
        if(err1){
          console.log(msg1, err1)
          cb()
        } else {
          generateProofInputs(endBalance, outgoing, intermediateBalance, 'proof2Inputs', function(msg2, err2){
            if(err2){
              console.log(msg2, err2)
              cb()
            } else {
              handleExecuteProgram('./generateProof', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(msgGenerateProof){
                if(msgGenerateProof){
                  console.log('\n' + msgGenerateProof)
                  endBalance = startBalance
                  intermediateBalance = startBalance
                  incoming = 0
                  outgoing = 0
                }
                cb()
              })
            }
          })
        }
      })
    })
  })
  })
}

function handleInput(){
  console.log('Start balance:', startBalance)
  console.log('Total incoming payments:', incoming)
  console.log('Total outgoing payments:', outgoing)
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
          incoming = 0
          outgoing = 0
          
          handleInput()
        }
      })
    } else {
      console.log('Quiting...')
    }
  })
}

handleInput()
