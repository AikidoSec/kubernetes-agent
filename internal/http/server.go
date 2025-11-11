package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"aikidoSec.kubernetesAgent/internal/http/controllers"
)

func ListenAndServe(ctx context.Context, logger *slog.Logger, port int, controllers ...controllers.Controller) error {
	mux := http.NewServeMux()

	for _, c := range controllers {
		c.RegisterRoutes(mux)
	}

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("starting http server", "port", ":"+strconv.Itoa(port))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("error while serving HTTP server", "err", err)
			return
		}
	}()

	sig := <-exit
	logger.Info("received signal, waiting 30 seconds to finish work", "signal", sig.String())
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("error while shutting down server: %w", err)
	}

	if ctx.Err() != nil {
		return fmt.Errorf("error while waiting for server to shutdown: %w", ctx.Err())
	}

	return nil
}
