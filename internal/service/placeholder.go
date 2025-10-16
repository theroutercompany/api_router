package service

// Placeholder provides a hook for future upstream orchestration services.
type Placeholder struct{}

// NewPlaceholder returns a no-op service instance for scaffolding.
func NewPlaceholder() *Placeholder {
	return &Placeholder{}
}
