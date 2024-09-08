# ToDo

## Bugs

- [ ] server todos
- [ ] pubsub publishes store some data in some cache which means
      ------- time ------->
      pub(channel, message): no-subscriber -> some-time-later -> sub(channel): get message even though publisher is no longer there
