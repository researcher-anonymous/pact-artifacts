package api

import (
	"errors"
	"fmt"
)

const (
	StatusOK                  = 200
	StatusBadRequest          = 400
	StatusInternalServerError = 500
)

type Project struct {
	ID   string
	Name string
}

type Response struct {
	StatusCode int
	Project    Project
	Err        error
}

type ProjectStore interface {
	FindProject(projectID string) (Project, error)
}

type Handler struct {
	store ProjectStore
}

func NewHandler(store ProjectStore) *Handler {
	return &Handler{store: store}
}

func (h *Handler) GetProject(projectID string) Response {
	if projectID == "" {
		return Response{
			StatusCode: StatusBadRequest,
			Err:        errors.New("project_id is required"),
		}
	}

	project, err := h.store.FindProject(projectID)
	if err != nil {
		return Response{
			StatusCode: StatusInternalServerError,
			Err:        fmt.Errorf("load project: %w", err),
		}
	}

	return Response{
		StatusCode: StatusOK,
		Project:    project,
	}
}

type MemoryProjectStore struct {
	projects map[string]Project
}

func NewMemoryProjectStore(projects []Project) *MemoryProjectStore {
	byID := make(map[string]Project, len(projects))
	for _, project := range projects {
		byID[project.ID] = project
	}
	return &MemoryProjectStore{projects: byID}
}

func (s *MemoryProjectStore) FindProject(projectID string) (Project, error) {
	project, ok := s.projects[projectID]
	if !ok {
		return Project{}, errors.New("project not found")
	}
	return project, nil
}
