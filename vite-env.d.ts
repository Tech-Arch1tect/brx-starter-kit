/// <reference types="vite/client" />

declare module '*.tsx' {
  const component: React.ComponentType<any>;
  export default component;
}