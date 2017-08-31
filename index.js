const spawn = require( 'child_process' ).spawn
const generateKeyPair = spawn( './generateKeyPair')
const test = spawn( './test')

const startOfVerificationKey = 'keypair.vk|start:'
const startOfProverKey = 'keypair.pk|start:'
const endOfKey = ':end'

let verificationKey = null
let proverKey = null

generateKeyPair.stdout.on( 'data', data => {
  let startIndex = data.toString().indexOf(startOfVerificationKey)
  if(startIndex > 0){ 
    let endIndex = data.toString().indexOf(endOfKey);
    verificationKey = data.toString().substring(startIndex+startOfVerificationKey.length, endIndex)
    console.log('verificationKey.length:', verificationKey.length)
  }

  startIndex = data.toString().indexOf(startOfProverKey)
  console.log('data:', data.toString())
  if(startIndex > 0){ 
    let endIndex = data.toString().indexOf(endOfKey);
    proverKey = data.toString().substring(startIndex+startOfProverKey.length, endIndex)
    console.log('proverKey.length:', proverKey.length)
  }
});

generateKeyPair.stderr.on( 'data', data => {
  console.log( `stderr: ${data}` )
});

generateKeyPair.on( 'close', code => {
  console.log( `child process exited with code ${code}` )
});
