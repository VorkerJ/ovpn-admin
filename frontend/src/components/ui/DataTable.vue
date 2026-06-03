<!--
  DataTable — table shell with sticky header + internal scroll.
  Used by CcdModal (routes table and exclusions table) and any other panel
  that needs "header pinned, body scrolls" behaviour inside a modal.
  Slots:
    - colgroup — <col> definitions; required for table-fixed layout so
      header cells align with body cells regardless of content width.
    - header  — <th> cells for the sticky header row.
    - body    — <tr> rows rendered when not empty; otherwise the
      built-in empty-state row is shown.
-->
<script setup>
defineProps({
  empty: { type: Boolean, default: false },
  emptyText: { type: String, default: 'Нет данных' },
  // Header colspan for the empty-state row — must match the number of
  // <col> entries the parent provides via the colgroup slot.
  colspan: { type: Number, default: 4 },
  // Tailwind max-height utility for the scroll container. Caller picks
  // a value that fits the modal it lives in (rows look weird at h-screen).
  maxHeight: { type: String, default: 'max-h-80' },
})
</script>

<template>
  <div :class="['rounded-md border border-border overflow-y-auto', maxHeight]">
    <table class="w-full text-sm table-fixed">
      <colgroup>
        <slot name="colgroup" />
      </colgroup>
      <thead class="sticky top-0 bg-card border-b border-border z-10">
        <tr>
          <slot name="header" />
        </tr>
      </thead>
      <tbody>
        <tr v-if="empty">
          <td
            :colspan="colspan"
            class="px-2 py-6 text-center text-sm text-muted-foreground"
          >
            {{ emptyText }}
          </td>
        </tr>
        <slot
          v-else
          name="body"
        />
      </tbody>
    </table>
  </div>
</template>
