import { onBeforeUnmount, onMounted, ref, type Ref } from 'vue'

// One clock for every countdown on the page: a single interval, started by
// the first component that needs it and stopped with the last one.
const now = ref(Date.now())
let users = 0
let timer: number | undefined

export function useNow(): Ref<number> {
  onMounted(() => {
    users += 1
    if (users === 1) {
      now.value = Date.now()
      timer = window.setInterval(() => {
        now.value = Date.now()
      }, 1000)
    }
  })
  onBeforeUnmount(() => {
    users -= 1
    if (users === 0) {
      window.clearInterval(timer)
      timer = undefined
    }
  })
  return now
}
