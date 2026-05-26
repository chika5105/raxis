import { MemoryRouter, type MemoryRouterProps } from "react-router-dom";

export function TestMemoryRouter(props: MemoryRouterProps) {
  return (
    <MemoryRouter
      {...props}
      future={{
        v7_startTransition: true,
        v7_relativeSplatPath: true,
        ...props.future,
      }}
    />
  );
}
