import { createRouter, createWebHistory } from 'vue-router';
import Register from '../views/Register.vue';
import Login from '../views/Login.vue';
import Account from '../views/Account.vue';
import { getToken } from '../token';

const routes = [
  { path: '/', redirect: '/login' },
  { path: '/register', component: Register },
  { path: '/login', component: Login },
  {
    path: '/account',
    component: Account,
    meta: { requiresAuth: true }
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes
});

router.beforeEach((to, _from, next) => {
  if (to.meta.requiresAuth && !getToken()) {
    next('/login');
    return;
  }
  next();
});

export default router;
