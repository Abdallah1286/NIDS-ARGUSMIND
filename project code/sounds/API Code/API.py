"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          Network Intrusion Detection API - FastAPI with Pre-processing       ║
║                                                                              ║
║  Model: XGBoost Classifier (AUC 99.86% | F1 98%)                            ║
║  Features: 5 (3 raw + 2 engineered)                                         ║
║  Classes: 8 attack types                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, ConfigDict
from contextlib import asynccontextmanager
import numpy as np
import pickle
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
import uvicorn
from typing import List, Dict, Optional
import logging
import joblib
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables
model: Optional[XGBClassifier] = None
scaler: Optional[StandardScaler] = None
app_start_time = datetime.now()

ATTACK_CLASSES = [
    "Backdoor",   # 0
    "Benign",     # 1
    "Bot",        # 2
    "DDoS",       # 3
    "DoS",        # 4
    "Exploits",   # 5
    "Generic",    # 6
    "scanning"    # 7
]

# Model file paths
MODEL_PATH = 'model.pkl'
SCALER_PATH = 'scaler.pkl'


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.
    Replaces the deprecated @app.on_event decorators.
    """
    # Startup: Load model and scaler
    global model, scaler, app_start_time
    
    try:
        # Load model
        logger.info(f"Loading model from: {MODEL_PATH}")
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        logger.info("✓ Model loaded successfully")
        
        # Load scaler
        logger.info(f"Loading scaler from: {SCALER_PATH}")
        scaler = joblib.load(SCALER_PATH)
        logger.info("✓ Scaler loaded successfully")
        
        # Log scaler statistics
        logger.info("Scaler Statistics:")
        feature_names = [
            "FLOW_DURATION_MILLISECONDS",
            "TCP_WIN_MAX_IN", 
            "OUT_BYTES",
            "pkts_per_ms_in",
            "avg_pkt_size_in"
        ]
        for i, name in enumerate(feature_names):
            logger.info(f"  {name}: mean={scaler.mean_[i]:.2f}, std={scaler.scale_[i]:.2f}")
        
        logger.info("="*70)
        logger.info("API Ready - Model and Scaler loaded successfully")
        logger.info("="*70)
        
        app_start_time = datetime.now()
        
    except FileNotFoundError as e:
        logger.error(f"✗ File not found: {e}")
        logger.error("Please ensure model and scaler files are in the correct location")
        raise
    except Exception as e:
        logger.error(f"✗ Error loading model/scaler: {e}")
        raise
    
    # Yield control to the application
    yield
    
    # Shutdown: Cleanup (if needed)
    logger.info("Shutting down API...")


app = FastAPI(
    title="Network Intrusion Detection API",
    description="Real-time network attack detection with automatic feature engineering",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class RawNetworkFeatures(BaseModel):
    """
    Raw network features that require pre-processing.
    These are the original features from the CSV.
    """
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "FLOW_DURATION_MILLISECONDS": 1000.0,
                "TCP_WIN_MAX_IN": 65535.0,
                "OUT_BYTES": 5000.0,
                "IN_BYTES": 1500.0,
                "IN_PKTS": 30.0,
                "DURATION_IN": 500.0
            }
        }
    )
    
    FLOW_DURATION_MILLISECONDS: float = Field(
        ..., 
        ge=0,
        description="Flow duration in milliseconds"
    )
    TCP_WIN_MAX_IN: float = Field(
        ..., 
        ge=0,
        description="Maximum TCP window size (incoming)"
    )
    OUT_BYTES: float = Field(
        ..., 
        ge=0,
        description="Total outbound bytes"
    )
    IN_BYTES: float = Field(
        ..., 
        ge=0,
        description="Total inbound bytes (for feature engineering)"
    )
    IN_PKTS: float = Field(
        ..., 
        ge=0,
        description="Total inbound packets (for feature engineering)"
    )
    DURATION_IN: float = Field(
        ..., 
        ge=0,
        description="Inbound duration in milliseconds (for feature engineering)"
    )
    
    @field_validator('IN_PKTS', 'DURATION_IN')
    @classmethod
    def check_zero_division(cls, v, info):
        """Validate to prevent division by zero issues"""
        if v < 0:
            raise ValueError(f"{info.field_name} must be non-negative")
        return v


class ProcessedFeatures(BaseModel):
    """
    Processed features ready for model prediction.
    Includes engineered features.
    """
    FLOW_DURATION_MILLISECONDS: float
    TCP_WIN_MAX_IN: float
    OUT_BYTES: float
    pkts_per_ms_in: float
    avg_pkt_size_in: float


class PredictionResponse(BaseModel):
    """Response model for single prediction"""
    predicted_class: str = Field(..., description="Predicted attack type")
    predicted_class_id: int = Field(..., description="Numeric class ID")
    confidence: float = Field(..., description="Prediction confidence (0-1)")
    all_probabilities: Dict[str, float] = Field(..., description="Probabilities for all classes")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    features_used: ProcessedFeatures = Field(..., description="Processed features used for prediction")


class BatchPredictionRequest(BaseModel):
    """Request model for batch predictions"""
    samples: List[RawNetworkFeatures] = Field(..., min_length=1, max_length=1000)


class BatchPredictionResponse(BaseModel):
    """Response model for batch predictions"""
    predictions: List[PredictionResponse]
    total_predictions: int
    average_confidence: float
    attack_distribution: Dict[str, int]
    total_processing_time_ms: float


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    model_loaded: bool
    scaler_loaded: bool
    api_version: str
    uptime_seconds: float


class ModelInfoResponse(BaseModel):
    """Model information response"""
    model_type: str
    classes: List[str]
    total_classes: int
    features: List[str]
    model_performance: Dict[str, str]


def engineer_features(raw_features: RawNetworkFeatures) -> ProcessedFeatures:
    """
    Apply feature engineering to raw network features.
    
    Engineered Features:
    1. pkts_per_ms_in = IN_PKTS / (DURATION_IN + 1)
    2. avg_pkt_size_in = IN_BYTES / (IN_PKTS + 1)
    
    The "+1" prevents division by zero.
    """
    
    # Calculate engineered features
    pkts_per_ms_in = raw_features.IN_PKTS / (raw_features.DURATION_IN + 1)
    avg_pkt_size_in = raw_features.IN_BYTES / (raw_features.IN_PKTS + 1)
    
    # Create processed features
    processed = ProcessedFeatures(
        FLOW_DURATION_MILLISECONDS=raw_features.FLOW_DURATION_MILLISECONDS,
        TCP_WIN_MAX_IN=raw_features.TCP_WIN_MAX_IN,
        OUT_BYTES=raw_features.OUT_BYTES,
        pkts_per_ms_in=float(pkts_per_ms_in),
        avg_pkt_size_in=float(avg_pkt_size_in)
    )
    
    return processed


def preprocess_features(processed_features: ProcessedFeatures) -> np.ndarray:
    """
    Convert processed features to numpy array and apply scaling.
    
    Feature order (CRITICAL - must match training order):
    1. FLOW_DURATION_MILLISECONDS
    2. TCP_WIN_MAX_IN
    3. OUT_BYTES
    4. pkts_per_ms_in
    5. avg_pkt_size_in
    """
    import warnings
    
    features_array = np.array([[
        processed_features.FLOW_DURATION_MILLISECONDS,
        processed_features.TCP_WIN_MAX_IN,
        processed_features.OUT_BYTES,
        processed_features.pkts_per_ms_in,
        processed_features.avg_pkt_size_in
    ]], dtype=np.float32)
    
    # Check for NaN or Inf
    if np.isnan(features_array).any():
        raise ValueError("NaN values detected in features")
    if np.isinf(features_array).any():
        raise ValueError("Inf values detected in features")
    
    # Apply StandardScaler (suppress feature name warning)
    with warnings.catch_warnings():
        warnings.filterwarnings('ignore', message='X does not have valid feature names')
        scaled_features = scaler.transform(features_array)
    
    return scaled_features


def make_prediction(scaled_features: np.ndarray) -> tuple:
    """
    Make prediction using the trained model.
    Returns: (predicted_class_id, probabilities)
    """
    probabilities = model.predict_proba(scaled_features)[0]
    predicted_class_id = int(np.argmax(probabilities))
    
    return predicted_class_id, probabilities


@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Network Intrusion Detection API",
        "version": "2.0.0",
        "status": "online",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
        "model_info": "/model/info"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    uptime = (datetime.now() - app_start_time).total_seconds()
    
    return HealthResponse(
        status="healthy" if (model is not None and scaler is not None) else "unhealthy",
        model_loaded=model is not None,
        scaler_loaded=scaler is not None,
        api_version="2.0.0",
        uptime_seconds=uptime
    )


@app.get("/model/info", response_model=ModelInfoResponse)
async def get_model_info():
    """Get model information and configuration"""
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    return ModelInfoResponse(
        model_type="XGBoost Classifier",
        classes=ATTACK_CLASSES,
        total_classes=len(ATTACK_CLASSES),
        features=[
            "FLOW_DURATION_MILLISECONDS",
            "TCP_WIN_MAX_IN",
            "OUT_BYTES",
            "pkts_per_ms_in (engineered)",
            "avg_pkt_size_in (engineered)"
        ],
        model_performance={
            "AUC": "99.86%",
            "Weighted F1-Score": "98%",
            "Overall Accuracy": "~98%"
        }
    )


@app.get("/model/classes")
async def get_classes():
    """Get list of attack classes with IDs"""
    return {
        "classes": ATTACK_CLASSES,
        "total_classes": len(ATTACK_CLASSES),
        "class_mapping": {i: cls for i, cls in enumerate(ATTACK_CLASSES)}
    }


@app.post("/predict", response_model=PredictionResponse)
async def predict(raw_features: RawNetworkFeatures):
    """
    Make a single prediction with automatic feature engineering.
    
    Steps:
    1. Receive raw features
    2. Engineer features (pkts_per_ms_in, avg_pkt_size_in)
    3. Scale features using StandardScaler
    4. Make prediction
    5. Return results with probabilities
    """
    
    if model is None or scaler is None:
        raise HTTPException(status_code=503, detail="Model or scaler not loaded")
    
    start_time = datetime.now()
    
    try:
        # Step 1: Feature Engineering
        processed_features = engineer_features(raw_features)
        logger.debug(f"Engineered features: {processed_features}")
        
        # Step 2: Pre-processing (scaling)
        scaled_features = preprocess_features(processed_features)
        
        # Step 3: Prediction
        predicted_class_id, probabilities = make_prediction(scaled_features)
        predicted_class = ATTACK_CLASSES[predicted_class_id]
        confidence = float(probabilities[predicted_class_id])
        
        # Step 4: Create probability dictionary
        all_probs = {
            ATTACK_CLASSES[i]: float(probabilities[i])
            for i in range(len(ATTACK_CLASSES))
        }
        
        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        logger.info(f"Prediction: {predicted_class} (confidence: {confidence:.3f})")
        
        return PredictionResponse(
            predicted_class=predicted_class,
            predicted_class_id=predicted_class_id,
            confidence=confidence,
            all_probabilities=all_probs,
            processing_time_ms=processing_time,
            features_used=processed_features
        )
        
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")


@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(request: BatchPredictionRequest):
    """
    Make batch predictions with automatic feature engineering.
    Maximum 1000 samples per request.
    """
    
    if model is None or scaler is None:
        raise HTTPException(status_code=503, detail="Model or scaler not loaded")
    
    start_time = datetime.now()
    
    try:
        predictions = []
        attack_counts = {cls: 0 for cls in ATTACK_CLASSES}
        total_confidence = 0.0
        
        for raw_features in request.samples:
            # Feature engineering
            processed_features = engineer_features(raw_features)
            
            # Pre-processing
            scaled_features = preprocess_features(processed_features)
            
            # Prediction
            predicted_class_id, probabilities = make_prediction(scaled_features)
            predicted_class = ATTACK_CLASSES[predicted_class_id]
            confidence = float(probabilities[predicted_class_id])
            
            all_probs = {
                ATTACK_CLASSES[i]: float(probabilities[i])
                for i in range(len(ATTACK_CLASSES))
            }
            
            # Accumulate statistics
            attack_counts[predicted_class] += 1
            total_confidence += confidence
            
            predictions.append(PredictionResponse(
                predicted_class=predicted_class,
                predicted_class_id=predicted_class_id,
                confidence=confidence,
                all_probabilities=all_probs,
                processing_time_ms=0.0,  # Individual time not tracked in batch
                features_used=processed_features
            ))
        
        total_processing_time = (datetime.now() - start_time).total_seconds() * 1000
        avg_confidence = total_confidence / len(predictions) if predictions else 0.0
        
        logger.info(f"Batch prediction completed: {len(predictions)} samples in {total_processing_time:.2f}ms")
        
        return BatchPredictionResponse(
            predictions=predictions,
            total_predictions=len(predictions),
            average_confidence=avg_confidence,
            attack_distribution=attack_counts,
            total_processing_time_ms=total_processing_time
        )
        
    except ValueError as e:
        logger.error(f"Validation error in batch: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        raise HTTPException(status_code=500, detail=f"Batch prediction failed: {str(e)}")


@app.websocket("/ws/predict")
async def websocket_predict(websocket: WebSocket):
    """
    WebSocket endpoint for real-time predictions.
    
    Client sends: RawNetworkFeatures (JSON)
    Server returns: PredictionResponse (JSON)
    """
    await websocket.accept()
    logger.info("⚡ WebSocket connection established")
    
    try:
        while True:
            # Receive data
            data = await websocket.receive_json()
            
            try:
                # Parse raw features
                raw_features = RawNetworkFeatures(**data)
                
                # Feature engineering
                processed_features = engineer_features(raw_features)
                
                # Pre-processing
                scaled_features = preprocess_features(processed_features)
                
                # Prediction
                predicted_class_id, probabilities = make_prediction(scaled_features)
                predicted_class = ATTACK_CLASSES[predicted_class_id]
                confidence = float(probabilities[predicted_class_id])
                
                all_probs = {
                    ATTACK_CLASSES[i]: float(probabilities[i])
                    for i in range(len(ATTACK_CLASSES))
                }
                
                # Send response
                response = {
                    "predicted_class": predicted_class,
                    "predicted_class_id": predicted_class_id,
                    "confidence": confidence,
                    "all_probabilities": all_probs,
                    "timestamp": datetime.now().isoformat()
                }
                
                await websocket.send_json(response)
                
            except Exception as e:
                error_response = {
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                await websocket.send_json(error_response)
    
    except WebSocketDisconnect:
        logger.info("⚠ WebSocket disconnected")
    except Exception as e:
        logger.error(f"❌ WebSocket error: {e}")
        try:
            await websocket.close(code=1011, reason="Internal server error")
        except:
            pass


if __name__ == "__main__":
    uvicorn.run(
        "sssss:app",  # Changed from "main:app" to match your filename
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        access_log=True
    )
















    