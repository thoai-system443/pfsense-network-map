import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A parsed config never changes while it sits in the backend's memory,
      // so refetching on focus only costs work.
      refetchOnWindowFocus: false,
      retry: false,
      staleTime: Infinity,
    },
  },
});
