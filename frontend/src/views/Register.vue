<template>
  <BrandCard>
    <div class="px-8 py-10 space-y-8">
      <div class="space-y-2 text-slate-200">
        <h2 class="text-3xl font-semibold">Create your  account</h2>
        <p class="text-sm text-slate-400">
          Join the service and unlock seamless, password-less vibes.
        </p>
      </div>
      <form class="space-y-5" @submit.prevent="submit">
        <div class="space-y-2">
          <label class="block text-sm font-medium text-slate-300" for="full_name">Full name</label>
          <input
            id="full_name"
            v-model="form.full_name"
            type="text"
            required
            class="w-full rounded-xl bg-slate-800/70 border border-slate-700 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-amber-300"
          />
        </div>
        <div class="space-y-2">
          <label class="block text-sm font-medium text-slate-300" for="email">Email</label>
          <input
            id="email"
            v-model="form.email"
            type="email"
            required
            class="w-full rounded-xl bg-slate-800/70 border border-slate-700 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-amber-300"
          />
        </div>
        <div class="space-y-2">
          <label class="block text-sm font-medium text-slate-300" for="password">Password</label>
          <input
            id="password"
            v-model="form.password"
            type="password"
            required
            minlength="6"
            class="w-full rounded-xl bg-slate-800/70 border border-slate-700 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-amber-300"
          />
        </div>
        <p v-if="error" class="text-sm text-rose-300">{{ error }}</p>
        <button
          type="submit"
          class="w-full py-3 rounded-xl bg-amber-300 text-slate-900 font-semibold shadow hover:bg-amber-200"
          :disabled="loading"
        >
          {{ loading ? 'Creating account…' : 'Create account' }}
        </button>
      </form>
      <p class="text-sm text-slate-400 text-center">
        Already a member?
        <router-link to="/login" class="font-medium">Sign in without passwords</router-link>
      </p>
    </div>
  </BrandCard>
</template>

<script setup>
import { reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import BrandCard from '../components/BrandCard.vue';
import { registerUser } from '../api';

const router = useRouter();
const loading = ref(false);
const error = ref('');
const form = reactive({
  full_name: '',
  email: '',
  password: ''
});

async function submit() {
  error.value = '';
  loading.value = true;
  try {
    await registerUser({ ...form });
    router.push('/login');
  } catch (err) {
    error.value = err?.response?.data?.message ?? 'Registration failed. Please try again.';
  } finally {
    loading.value = false;
  }
}
</script>
