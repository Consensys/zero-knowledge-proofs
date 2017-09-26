const {spawn} = require('child_process')

var proofGenerator
var proofCodeBlocking = false
var generatorIsRunning = false

function getMatches(string, regex) {
  var matches = [];
  var match;
  while (match = regex.exec(string)) {
    matches.push(match[0]);
  }
  return matches;
}

function getProofCodeBlocking(){
  return proofCodeBlocking
}

function setProofCodeBlocking(value){
  proofCodeBlocking=value
}

function getGeneratorRunning(){
  return generatorIsRunning
}

function shutDown(){
  proofGenerator.stdin.write('q\n')
}

function generateProof(){
  proofGenerator.stdin.write('p\n')
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
    setProofCodeBlocking(false)
    if(code=='1' || !succesfullyCompleted){
      cb(msgError)
    } else {
      cb(null)
    }
  })
}

function generateNewKeyPair(multiOrSingle, cb){
  var generateKeyPairProgram = multiOrSingle == 'multi' ? './payment_multi_generate_keypair' : './payment_in_out_generate_keypair'
  setProofCodeBlocking(true)
  if(getGeneratorRunning()==true){
    shutDown()
  }
  handleExecuteProgram(generateKeyPairProgram, 'Generating key pair...', 'The key pair has been generated and the keys written to files', 'The key pair failed\n\n', function(){
    cb()
  })
}

function loadProvingKey(multiOrSingle){
  console.log('Loading proving key from file.  This will take a few seconds')
  setProofCodeBlocking(true)
  if(multiOrSingle=='multi'){
    proofGenerator = spawn('./payment_multi_generate_proof')
  } else {
    proofGenerator = spawn('./payment_in_out_generate_proof')
  }
  generatorIsRunning = true

  proofGenerator.stdout.on('data', (data) => {
    dataString = data.toString()

    if(dataString.indexOf('Press enter p to generate a proof or q to quit')>-1){
      setProofCodeBlocking(false)
    }

    if(dataString.indexOf('System not satisfied!')>-1){
      console.log('Proof generation unsuccesful: System not satisfied')
      setProofCodeBlocking(false)
    }
    if(dataString.indexOf('Proving key loaded into memory')>-1){
      setProofCodeBlocking(false)
    }

    if(data.indexOf('Compute the proof')>-1){
      if(data.indexOf('(enter)')>-1){
        console.log('\nGenerating proof')
      } else {
        var matches = getMatches(dataString, /\[[0-9]{0,2}.[0-9]*s/g)
        var noSecs = matches[1].substring(1,matches[1].length)
        console.log('\nProof generation ended:', noSecs)
        setProofCodeBlocking(false)
      }
    } else {
      process.stdout.write('.')
    }

  })

  proofGenerator.stderr.on('data', (data) => {
    console.log(data.toString())
  })

  proofGenerator.on('exit', function (code) {
    generatorIsRunning = false
  })
}

function verifyProof(multiOrSingle, cb){
  var verifyProofProgram = multiOrSingle == 'multi' ? './payment_multi_verify_proof' : './payment_in_out_verify_proof'
  handleExecuteProgram(verifyProofProgram, '', '', 'The proof verification failed\n\n', function(verifyErr){
    cb(verifyErr)
  })
}

exports.LoadProvingKey = loadProvingKey
exports.SetProofCodeBlocking = setProofCodeBlocking
exports.GetProofCodeBlocking = getProofCodeBlocking
exports.GetGeneratorRunning = getGeneratorRunning
exports.ShutDown = shutDown
exports.GenerateNewKeyPair = generateNewKeyPair
exports.GenerateProof = generateProof
exports.VerifyProof = verifyProof
