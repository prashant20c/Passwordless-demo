<template>
  <div class="max-w-lg mx-auto bg-slate-900/70 border border-slate-700/70 rounded-3xl shadow-xl overflow-hidden">
    <div class="bg-gradient-to-r from-purple-500 to-amber-400 text-slate-900">
      <div class="px-8 py-6 flex items-center gap-4">
        <div class="w-12 h-12 rounded-full bg-white/80 flex items-center justify-center font-bold text-lg">PP</div>
        <div>
          <p class="text-xs uppercase tracking-widest text-slate-800/80">Prashant20c</p>
          <h1 class="text-2xl font-semibold">Passwordless Demo</h1>
        </div>
      </div>
    </div>
    <slot />
  </div>
</template>
