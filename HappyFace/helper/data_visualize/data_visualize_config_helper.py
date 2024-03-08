class DataVisualizeConfigHelper:
    IMAGE_RESOLUTION = (350, 350)
    BAR_COLOR = "blue"
    BAR_CHART_TITLE = "Overall Face Emotion Distribution"
    BAR_CHART_X_AXIS_NAME = "emotion"
    BAR_CHART_Y_AXIS_NAME = "percentage"
    EMOTIONS_BASED_ON_POSITIVITY = dict(
        positive=[
            "happy",
            "neutral",
            "surprise"
        ],
        negative=[
            "anger",
            "contempt",
            "disgust",
            "fear",
            "sad"
        ]
    )
    PIE_CHART_POS_SEGMENT_COLOR = "#3732c2"
    PIE_CHART_NEG_SEGMENT_COLOR = "#c23239"
    PIE_CHART_FONT_SIZE = 12
    PIE_CHART_TITLE = "Face Emotion Distribution based on Positivity"
