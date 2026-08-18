// Package handlers provides route registration for admin console endpoints
package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// DashboardRoutes registers dashboard-related routes
func DashboardRoutes(router *gin.RouterGroup, handler *DashboardHandler) {
	dashboard := router.Group("/dashboard")
	{
		dashboard.GET("", handler.GetDashboardStats)
		dashboard.GET("/metrics", handler.GetMetrics)
		dashboard.POST("/refresh", handler.RefreshCache)
	}
}

// SettingsRoutes registers settings-related routes. Mutating routes (update,
// reset) are guarded by adminMW so that only admins can change org-wide
// security/password policy; read and password-validation routes stay open to
// any authenticated caller. If adminMW is nil the guard is skipped.
func SettingsRoutes(router *gin.RouterGroup, handler *SettingsHandler, adminMW gin.HandlerFunc) {
	settings := router.Group("/settings")
	{
		settings.GET("", handler.GetSettings)
		settings.GET("/json", handler.GetSettingsJSON)
		settings.POST("/validate-password", handler.ValidatePassword)
	}

	// Mutations require admin.
	mutate := router.Group("/settings")
	if adminMW != nil {
		mutate.Use(adminMW)
	}
	{
		mutate.PUT("", handler.UpdateSettings)
		mutate.POST("/reset", handler.ResetSettings)
	}
}

// RegisterAllRoutes registers all admin console routes. adminMW guards the
// mutating settings endpoints; pass admin.RequireAdmin() from the caller.
func RegisterAllRoutes(router *gin.RouterGroup, db *pgxpool.Pool, logger *zap.Logger, adminMW gin.HandlerFunc) {
	dashboardHandler := NewDashboardHandler(logger, db)
	settingsHandler := NewSettingsHandler(logger, db)

	// Dashboard routes
	DashboardRoutes(router, dashboardHandler)

	// Settings routes
	SettingsRoutes(router, settingsHandler, adminMW)
}
