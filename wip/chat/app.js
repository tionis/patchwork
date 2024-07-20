const ul = document.querySelector('#chat')
const username = document.querySelector('#username')
const input = document.querySelector('#message')
const sendButton = document.querySelector('#send')
const chatId = document.querySelector('#chatId')

const handleEvtSource = evtSource => {
  evtSource.onmessage = function(e) {
    let data = JSON.parse(e.data)
    let msg = document.createElement('li')
    msg.innerHTML = `<b>${data.author}</b>: ${data.text}`
    ul.appendChild(msg)
    ul.scroll(0,9e9)
  }
}

document.addEventListener('DOMContentLoaded', () => {
  let CHAT_ID = (Math.random() + 1).toString(36).substring(7)
  chatId.value = CHAT_ID

  sendButton.addEventListener('click', () => {
    const message = JSON.stringify({
      author: username.value,
      text: input.value,
    })

    fetch(`https://${CHAT_ID}`, {
      method: 'POST',
      mode: 'no-cors',
      body: `data: ${message}\n\n`,
    })
    input.value = ''
  })

  let evtSource = new EventSource(`https://patch.tionis.dev/p/pubsub/${CHAT_ID}?mime=text%2Fevent-stream&persist=true`)

  chatId.addEventListener('change', e => {
    evtSource.close()
    CHAT_ID = e.target.value
    evtSource = new EventSource(`https://patch.tionis.dev/p/pubsub/${CHAT_ID}?mime=text%2Fevent-stream&persist=true`)
    
    handleEvtSource(evtSource)
  })
  
  handleEvtSource(evtSource)

})
