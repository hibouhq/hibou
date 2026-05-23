import { createApp } from 'vue'
import { createPinia } from 'pinia'

import router from '@/router'
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
    return { name: 'login' }
  }

  if (to.name === 'login' && auth.isAuthenticated) {
    return { name: 'dashboard' }
  }

  return true
})

app.mount('#app')