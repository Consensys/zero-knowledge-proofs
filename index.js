var prompt = require('prompt');

const {exec} = require( 'child_process' )

function handleGenerateKeyPair(cb){

  exec('./generateKeyPair', (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.log(`stderr: ${stderr}`);
    cb()
  });

}

function handleGenerateProof(cb){
  console.log('Loading Proving Key from file... (this takes a few seconds)')
  exec('./generateProof', (error, stdout, stderr) => {
    console.log(`stdout: ${stdout}`);
    if (error) {
      console.error(`exec error: ${error}`);
      console.log('The proof generation failed\n\n');
    }
    if(stderr){
      console.log(`stderr: ${stderr}`);
      console.log('The proof generation failed\n\n');
    }
    cb()
  });
}

function handleVerifyProof(cb){
  exec('./verifyProof', (error, stdout, stderr) => {
    console.log(`stdout: ${stdout}`);
    if (error) {
      console.error(`exec error: ${error}`);
      console.log('The proof verification failed\n\n');
    }
    if(stderr){
      console.log(`stderr: ${stderr}`);
      console.log('The proof verification failed\n\n');
    }
    cb()
  });
}

function handleInput(){
  console.log('Please select an option:\n1) Create a new key pair\n2) Generate a proof\n3) Verify a proof\n4) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleGenerateKeyPair(function(){
        handleInput()
      })
    } else if (answer.option == 2){
      handleGenerateProof(function(){
        handleInput()
      })
    } else if(answer.option == 3){
      handleVerifyProof(function(){
        handleInput()
      })
    } else {
      console.log('Quiting...')
    }
  })
}

handleInput()
