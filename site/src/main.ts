import { createApp } from 'vue'
import { createPinia } from 'pinia'

import router from '@/router'
import { rememberReturnTo, takeReturnTo } from '@/lib/returnTo'
import { installTooltips } from '@/lib/tooltip'
import { useAuthStore } from '@/stores/auth'
import App from './App.vue'
import './style/main.css'

const app = createApp(App)

const pinia = createPinia()

app.use(pinia)
app.use(router)

router.beforeEach(async (to) => {
  const auth = useAuthStore(pinia)

  if (auth.loading) {
    await auth.fetchUser()
  }

  if (!to.meta.public && !auth.isAuthenticated) {
    rememberReturnTo(to.fullPath)
    return { name: 'login' }
  }

  if (auth.isAuthenticated) {
    // Back from sign-in: resume the page that required it.
    const resume = takeReturnTo()
    if (resume && resume !== to.fullPath) {
      return resume
    }
  }

  if (to.name === 'login' && auth.isAuthenticated) {
    return { name: 'orgs' }
  }

  return true
})

app.mount('#app')
installTooltips()
