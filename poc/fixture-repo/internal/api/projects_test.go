package api

import (
	"errors"
	"testing"
)

func TestGetProjectRejectsEmptyProjectID(t *testing.T) {
	handler := NewHandler(NewMemoryProjectStore([]Project{
		{ID: "pact", Name: "PACT artifact"},
	}))

	response := handler.GetProject("")

	if response.StatusCode != StatusBadRequest {
		t.Fatalf("empty project_id status = %d, want %d", response.StatusCode, StatusBadRequest)
	}
	if response.Err == nil {
		t.Fatal("empty project_id error is nil, want validation error")
	}
}

func TestGetProjectReturnsExistingProject(t *testing.T) {
	handler := NewHandler(NewMemoryProjectStore([]Project{
		{ID: "pact", Name: "PACT artifact"},
	}))

	response := handler.GetProject("pact")

	if response.StatusCode != StatusOK {
		t.Fatalf("existing project status = %d, want %d", response.StatusCode, StatusOK)
	}
	if response.Project.ID != "pact" {
		t.Fatalf("project ID = %q, want %q", response.Project.ID, "pact")
	}
	if response.Err != nil {
		t.Fatalf("existing project error = %v, want nil", response.Err)
	}
}

func TestGetProjectReturnsInternalErrorForStoreFailure(t *testing.T) {
	handler := NewHandler(failingStore{})

	response := handler.GetProject("pact")

	if response.StatusCode != StatusInternalServerError {
		t.Fatalf("store failure status = %d, want %d", response.StatusCode, StatusInternalServerError)
	}
	if response.Err == nil {
		t.Fatal("store failure error is nil, want wrapped store error")
	}
}

type failingStore struct{}

func (failingStore) FindProject(projectID string) (Project, error) {
	return Project{}, errors.New("database unavailable")
}
