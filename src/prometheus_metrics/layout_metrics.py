from prometheus_client import CollectorRegistry, Gauge, generate_latest
import yaml


def prometheus_metrics_from_json(json_metrics: dict,
                                 prometheus_metrics_conf='/opt/backup/prometheus_metrics/metrics_config.yaml') -> str:
    """
    Return string with prometheus metrics from json metrics and yaml config from this directory.
    :param json_metrics: metrics in json format
    :param prometheus_metrics_conf: yaml configuration of prometheus metrics
    :return: multi-line string with prometheus metrics
    """
    reg = CollectorRegistry()

    with open(prometheus_metrics_conf) as f:
        metrics_config = yaml.safe_load(f)

    def gauge_from_json(current_part_of_json: dict, path_in_json=None) -> None:
        """
        Make gauges from json metrics.
        Recursive function.
        :param current_part_of_json: unexplored part of json metrics
        :param path_in_json: path in explored part of json
        :return: None
        """
        if path_in_json is None:
            path_in_json = []

        for json_key, json_value in current_part_of_json.items():
            new_path_in_json = list(path_in_json)
            new_path_in_json.append(json_key)  # path with current key
            if isinstance(json_value, dict):  # if json_value is dict then json_value is not a metric
                gauge_from_json(json_value, new_path_in_json)  # recursive call with "subjson" and new path
            else:  # if json_value is dict then json_value is a metric and json_key - name of this metric
                # get info about prometheus version of this metric: name, description and labels
                current_metric_conf = get_value_from_dict(metrics_config, new_path_in_json)
                if current_metric_conf is not None:  # if this prometheus metric exists
                    metric_name = current_metric_conf[0]
                    metric_desc = current_metric_conf[1]
                    metric_label_names = []
                    metric_label_values = []
                    if len(current_metric_conf) > 2:  # if info about labels exists
                        # path_to_label_value is path in the json
                        for label_name, path_to_label_value in current_metric_conf[2].items():
                            metric_label_names.append(label_name)
                            metric_label_values.append(get_value_from_dict(json_metrics,
                                                                           path_to_label_value.split('.')))
                    if bool(metric_label_names):
                        g = Gauge(metric_name, metric_desc, metric_label_names, registry=reg)
                        g.labels(*metric_label_values).set(json_value)
                    else:
                        g = Gauge(metric_name, metric_desc, registry=reg)
                        g.set(json_value)

    gauge_from_json(json_metrics)

    return generate_latest(reg).decode('utf-8')  # result of this function is a byte string which coded in utf-8


def get_value_from_dict(value, path: list):
    """
    Return value from dict (in param value) by given path.
    If value isn't dict or None and path is not empty, raise exception.
    Recursive function.
    :param value: dict, None (if path is not empty) or something else
    :param path: list with keys for dict
    :return: value given by path from dict or None if there is no key here
    """
    try:
        if value is None:
            return None
        if bool(path):
            key = path.pop(0)
            return get_value_from_dict(value.get(key, None), path)
        return value
    except Exception as e:
        raise e
