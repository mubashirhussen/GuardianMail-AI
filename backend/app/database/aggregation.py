from typing import List, Dict, Any

class AggregationBuilder:
    """Fluid API builder facilitating programmatic construction of MongoDB aggregation pipelines."""
    
    def __init__(self):
        self.pipeline: List[Dict[str, Any]] = []

    def match(self, criteria: Dict[str, Any]) -> 'AggregationBuilder':
        """Inject match filtering stage."""
        self.pipeline.append({"$match": criteria})
        return self

    def group(self, group_id: Any, accumulators: Dict[str, Any]) -> 'AggregationBuilder':
        """Inject group aggregation stage."""
        stage = {"_id": group_id}
        stage.update(accumulators)
        self.pipeline.append({"$group": stage})
        return self

    def project(self, fields: Dict[str, Any]) -> 'AggregationBuilder':
        """Inject project transformation stage."""
        self.pipeline.append({"$project": fields})
        return self

    def sort(self, fields: Dict[str, int]) -> 'AggregationBuilder':
        """Inject sort sorting stage."""
        self.pipeline.append({"$sort": fields})
        return self

    def skip(self, value: int) -> 'AggregationBuilder':
        """Inject skip pagination offset stage."""
        self.pipeline.append({"$skip": value})
        return self

    def limit(self, value: int) -> 'AggregationBuilder':
        """Inject limit pagination size stage."""
        self.pipeline.append({"$limit": value})
        return self

    def lookup(self, from_coll: str, local_field: str, foreign_field: str, as_name: str) -> 'AggregationBuilder':
        """Inject lookup left outer join mapping stage."""
        self.pipeline.append({
            "$lookup": {
                "from": from_coll,
                "localField": local_field,
                "foreignField": foreign_field,
                "as": as_name
            }
        })
        return self

    def facet(self, facets: Dict[str, List[Dict[str, Any]]]) -> 'AggregationBuilder':
        """Inject facet analytics classification stage."""
        self.pipeline.append({"$facet": facets})
        return self

    def build(self) -> List[Dict[str, Any]]:
        """Return the compiled aggregation array pipeline list."""
        return self.pipeline
