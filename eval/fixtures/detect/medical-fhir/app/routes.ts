export function getObservation(id: string) { return fetch(`/fhir/Observation/${id}`); }
