<template>
  <div class="min-h-screen bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 text-slate-100">
    <header class="py-12 text-center space-y-2">
      <p class="uppercase tracking-[0.4em] text-xs text-amber-200/70">Trustlogin</p>
      <h1 class="text-4xl font-semibold">Login With Trust, Not Passwords.</h1>
      <p class="text-sm text-slate-400">Approve every sign-in from your trusted device—no passwords, just trust.</p>
    </header>
    <main class="flex justify-center items-start px-4 pb-16">
      <router-view />
    </main>
  </div>
</template>
