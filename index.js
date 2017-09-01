var prompt = require('prompt');

const {exec} = require( 'child_process' )

function handleExecuteProgram(programName, msgStart, msgEnd, msgError, cb){
  console.log(msgStart)
  exec(programName, (error, stdout, stderr) => {
    console.log(`stdout: ${stdout}`)
    if (error) {
      console.error(`exec error: ${error}`)
      console.log(msgError)
    }
    if(stderr){
      console.log(`stderr: ${stderr}`)
      console.log(msgError)
    }
    console.log(msgEnd)
    cb()
  });
}

function handleInput(){
  console.log('Please select an option:\n1) Create a new key pair\n2) Generate a proof\n3) Verify a proof\n4) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleExecuteProgram('./generateKeyPair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey and verificationKey)', 'The key pair failed\n\n', function(){
        handleInput()
      })
    } else if (answer.option == 2){
      handleExecuteProgram('./generateProof', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(){
        handleInput()
      })
    } else if(answer.option == 3){
      handleExecuteProgram('./verifyProof', '', '', 'The proof verification failed\n\n', function(){
        handleInput()
      })
    } else {
      console.log('Quiting...')
    }
  })
}

handleInput()
